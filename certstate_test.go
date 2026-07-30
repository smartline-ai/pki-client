package pkiclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func makeCA(t *testing.T) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) leaf(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "n-01j9qk3m7x2v5tpb8w4h6n0zya"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("лист: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (ca testCA) leafFor(t *testing.T, pub *ecdsa.PublicKey, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "n-01j9qk3m7x2v5tpb8w4h6n0zya"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("лист на заданный ключ: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// clientLeafFor выпускает лист с ExtKeyUsage только clientAuth — форма, в
// которой Control Plane реально выдаёт вид client (control-plane/internal/pki
// .SignLeaf), в отличие от leaf()/leafFor() выше, которые несут serverAuth.
func (ca testCA) clientLeafFor(t *testing.T, pub *ecdsa.PublicKey, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "ops-laptop"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("клиентский лист: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (ca testCA) pool(t *testing.T) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(ca.pem) {
		t.Fatal("CA не добавился в пул")
	}
	return p
}

func TestInspectClassifies(t *testing.T) {
	ours := makeCA(t)
	foreign := makeCA(t)
	dir := t.TempDir()
	now := time.Now()

	write := func(name string, body []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatalf("запись %s: %v", name, err)
		}
		return p
	}

	cases := []struct {
		name string
		path string
		want CertState
	}{
		{"файла нет", filepath.Join(dir, "нет.pem"), CertAbsent},
		{"не PEM", write("мусор.pem", []byte("не сертификат")), CertUnparseable},
		{"просрочен", write("старый.pem", ours.leaf(t, now.Add(-time.Minute))), CertExpired},
		{"чужой CA", write("чужой.pem", foreign.leaf(t, now.Add(time.Hour))), CertForeignCA},
		{"валиден", write("хороший.pem", ours.leaf(t, now.Add(time.Hour))), CertValid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, _ := Inspect(c.path, ours.pool(t), KindNode, now)
			if got != c.want {
				t.Fatalf("Inspect = %q, ожидалось %q", got, c.want)
			}
		})
	}
}

// Присутствующий, но нечитаемый сертификат обязан отличаться от
// отсутствующего: под ним может лежать валидное удостоверение, и функция,
// ради которой существует Inspect, — не дать спутать эти два случая.
// Каталог на месте файла сертификата — самый простой воспроизводимый способ
// получить ошибку чтения, которая не является os.ErrNotExist.
func TestInspectDistinguishesUnreadableFromAbsent(t *testing.T) {
	ours := makeCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.pem")
	if err := os.Mkdir(certPath, 0o755); err != nil {
		t.Fatalf("каталог вместо файла сертификата: %v", err)
	}

	state, cert, err := Inspect(certPath, ours.pool(t), KindNode, time.Now())
	if state != CertUnreadable {
		t.Fatalf("Inspect = %q, ожидалось %q", state, CertUnreadable)
	}
	if cert != nil {
		t.Fatal("нечитаемый сертификат не имеет права вернуть разобранный *x509.Certificate")
	}
	if err == nil {
		t.Fatal("нечитаемый сертификат обязан вернуть исходную ошибку чтения")
	}
}

// Переиспользование ключа — условие корректности пути повтора: вторая попытка
// join обязана нести тот же публичный ключ, иначе CP её отвергнет.
func TestLoadOrCreateKeyReusesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-key.pem")

	first, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("первый вызов: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("файл ключа не создан: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("режим ключа %v, ожидался 0600", info.Mode().Perm())
	}

	second, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("второй вызов: %v", err)
	}
	if !first.PublicKey.Equal(&second.PublicKey) {
		t.Fatal("повторный вызов обязан вернуть тот же ключ, а не сгенерировать новый")
	}
}

// Два конкурентных первых вызова (холодный старт, гонка) обязаны сойтись на
// одном ключе — том, что реально лежит на диске. Без атомарной публикации
// "выиграл ровно один" каждый проигравший генерирует свой ключ и, в
// зависимости от того, чья запись легла на диск последней, может вернуть
// вызывающему ключ, отличный от сохранённого — а именно это переиспользование
// ключа и обязано предотвращать (см. TestLoadOrCreateKeyReusesExisting).
func TestLoadOrCreateKeyConcurrentCallersConverge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-key.pem")
	const n = 32

	var start, ready, done sync.WaitGroup
	start.Add(1)
	ready.Add(n)
	done.Add(n)

	keys := make([]*ecdsa.PrivateKey, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			ready.Done()
			start.Wait()
			keys[i], errs[i] = LoadOrCreateKey(path)
		}(i)
	}
	ready.Wait() // все горутины уже дошли до старта, прежде чем его открыть
	start.Done()
	done.Wait() // и до чтения keys/errs ниже все обязаны закончить свой вызов

	// t.Fatalf в горутине — не по правилам testing.T, поэтому каждый вызов
	// LoadOrCreateKey пишет свой результат в errs/keys, а падаем мы уже
	// здесь, в теле теста, после того как все горутины завершились.
	for i, err := range errs {
		if err != nil {
			t.Fatalf("вызов %d: %v", i, err)
		}
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение итогового файла ключа: %v", err)
	}
	block, _ := pem.Decode(onDisk)
	if block == nil {
		t.Fatal("итоговый файл ключа не PEM")
	}
	diskKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("разбор итогового ключа на диске: %v", err)
	}

	for i, k := range keys {
		if !k.PublicKey.Equal(&diskKey.PublicKey) {
			t.Fatalf("вызов %d вернул ключ, отличный от того, что реально лежит на диске", i)
		}
	}
}
