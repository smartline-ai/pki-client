package pkiclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Рубеж считается от фактического срока листа, а не от конфига: участник не
// знает TTL, которым CP его выписал, и обязан вывести его из
// NotBefore/NotAfter.
func TestNeedsRenewalUsesCertificateOwnLifetime(t *testing.T) {
	issued := time.Now()
	cert := &x509.Certificate{
		NotBefore: issued,
		NotAfter:  issued.Add(90 * 24 * time.Hour),
	}
	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"сразу после выпуска", issued, false},
		{"на 59-й день", issued.Add(59 * 24 * time.Hour), false},
		{"на 61-й день", issued.Add(61 * 24 * time.Hour), true},
		{"после истечения", issued.Add(91 * 24 * time.Hour), true},
	}
	for _, c := range cases {
		if got := NeedsRenewal(cert, c.at); got != c.want {
			t.Errorf("%s: NeedsRenewal = %v, ожидалось %v", c.name, got, c.want)
		}
	}
	if !NeedsRenewal(nil, issued) {
		t.Error("отсутствующий сертификат обязан требовать обновления")
	}
}

// Смысл источника: сервер, поднятый месяцы назад, обязан начать предъявлять
// новый сертификат без перезапуска.
func TestCertSourceSwapsWithoutRestart(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.pem")
	keyPath := filepath.Join(dir, "node-key.pem")

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	writeFile(t, certPath, ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour)))

	var src CertSource
	if err := src.Load(certPath, keyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}
	first, err := src.Get(&tls.ClientHelloInfo{})
	if err != nil || first == nil {
		t.Fatalf("Get: cert=%v err=%v", first, err)
	}

	writeFile(t, certPath, ca.leafFor(t, &key.PublicKey, time.Now().Add(48*time.Hour)))
	if err := src.Load(certPath, keyPath); err != nil {
		t.Fatalf("повторный Load: %v", err)
	}
	second, _ := src.Get(&tls.ClientHelloInfo{})
	if second == first {
		t.Fatal("после перезагрузки источник обязан отдавать новый сертификат")
	}
	if !second.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Fatal("новый сертификат обязан быть свежее старого")
	}
}

// Дополняет TestNeedsRenewalUsesCertificateOwnLifetime: тот тест целиком
// строится на 90-дневном сертификате, поэтому реализация с зашитыми
// константами 90/30 дней прошла бы его незамеченной. Здесь срок листа другой
// (30 дней), и порог обязан пропорционально сдвинуться вместе с ним — иначе
// проверяется не "своя треть срока", а совпадение с частным случаем теста.
func TestNeedsRenewalScalesWithCertificatesOwnLifetime(t *testing.T) {
	issued := time.Now()
	cert := &x509.Certificate{
		NotBefore: issued,
		NotAfter:  issued.Add(30 * 24 * time.Hour),
	}
	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"на 19-й день из 30 (до трети)", issued.Add(19 * 24 * time.Hour), false},
		{"на 21-й день из 30 (после трети)", issued.Add(21 * 24 * time.Hour), true},
	}
	for _, c := range cases {
		if got := NeedsRenewal(cert, c.at); got != c.want {
			t.Errorf("%s: NeedsRenewal = %v, ожидалось %v", c.name, got, c.want)
		}
	}
}

// RunRenewal обязан реагировать на отмену контекста немедленно, а не только
// по следующему тику: иначе остановка демона блокировалась бы до `every`,
// здесь заведомо больше разумного таймаута теста.
func TestRunRenewalReturnsPromptlyOnContextCancellation(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.pem")
	keyPath := filepath.Join(dir, "node-key.pem")

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	writeFile(t, certPath, ca.leafFor(t, &key.PublicKey, time.Now().Add(24*time.Hour)))

	var src CertSource
	if err := src.Load(certPath, keyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// Mode: control_plane — иначе тест проверял бы не отмену контекста
		// внутри тикера, а ворота I2 (см. TestRunRenewalSkipsOutsideControlPlaneMode
		// ниже), которые и без отмены возвращаются немедленно.
		RunRenewal(ctx, Deps{
			Mode: "control_plane",
			Log:  discardLog(),
		}, &src, time.Hour)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunRenewal не вернулся в течение секунды после отмены контекста при every=1h")
	}
}

// I2 финального ревью: RunRenewal обязан молчать вне control_plane точно так
// же, как Ensure/Join (ensure.go) — а не только «случайно» не срабатывать
// благодаря тому, что сертификат dev-1 живёт 3650 дней. Тест ставит every=1h
// и не отменяет контекст вовсе: если бы ворота были пропущены, RunRenewal
// заблокировался бы на тикере и done не закрылся бы за отведённую секунду.
func TestRunRenewalSkipsOutsideControlPlaneMode(t *testing.T) {
	for _, mode := range []string{"webhook", "none", ""} {
		t.Run(mode, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				RunRenewal(context.Background(), Deps{
					Mode: mode,
					Log:  discardLog(),
				}, &CertSource{}, time.Hour)
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatalf("RunRenewal(mode=%q) обязан вернуться немедленно, не дожидаясь тикера", mode)
			}
		})
	}
}

// Смысл порядка "файл, потом указатель" (§ решения задачи) проверяется не
// только по чтению кода: после успешного обновления диск и память обязаны
// сходиться на одном и том же сертификате, а не на двух разных.
func TestRenewOnceKeepsDiskAndMemoryInAgreement(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.pem")
	keyPath := filepath.Join(dir, "node-key.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writeFile(t, caPath, ca.pem)

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	writeFile(t, certPath, ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour)))

	var src CertSource
	if err := src.Load(certPath, keyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}

	newNotAfter := time.Now().Add(48 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaf := ca.leafFor(t, &key.PublicKey, newNotAfter)
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(leaf)})
	}))
	defer srv.Close()

	d := Deps{
		CAFile:   caPath,
		CertFile: certPath,
		KeyFile:  keyPath,
		PKIURL:   srv.URL,
		Identity: Identity{
			Kind: KindNode,
			CN:   "n-01j9qk3m7x2v5tpb8w4h6n0zya",
			IP:   net.ParseIP("10.0.0.5"),
		},
		Log: discardLog(),
	}

	if err := renewOnce(context.Background(), d, &src); err != nil {
		t.Fatalf("renewOnce: %v", err)
	}

	onDisk, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("чтение файла: %v", err)
	}
	block, _ := pem.Decode(onDisk)
	diskCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("разбор файла: %v", err)
	}

	inMemory, err := src.Get(nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if !diskCert.NotAfter.Equal(inMemory.Leaf.NotAfter) {
		t.Fatalf("диск (%s) и память (%s) разошлись после обновления", diskCert.NotAfter, inMemory.Leaf.NotAfter)
	}
	if !inMemory.Leaf.NotAfter.After(time.Now().Add(47 * time.Hour)) {
		t.Fatalf("in-memory сертификат не обновился: NotAfter=%s", inMemory.Leaf.NotAfter)
	}
}

// I3 финального ревью: renewOnce проверял только цепочку до прижатого CA, но
// не то, что выданный сертификат вообще выписан на ключ, который есть у
// участника. Сертификат, честно собирающийся в цепочку и всё же выданный не
// на тот ключ, раньше лёг бы на диск — и следующий рестарт нашёл бы ровно ту
// расколотую пару, из которой C2 не даёт выбраться. Зеркало
// TestJoinRejectsCertificateOnForeignKey (join_test.go) для пути обновления.
func TestRenewOnceRejectsCertificateOnForeignKey(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.pem")
	keyPath := filepath.Join(dir, "node-key.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writeFile(t, caPath, ca.pem)

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	staleCert := ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
	writeFile(t, certPath, staleCert)

	var src CertSource
	if err := src.Load(certPath, keyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}
	before, err := src.Get(nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("чужой ключ: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Верный CA (ca), но подписан на ключ, которого у участника нет.
		leaf := ca.leafFor(t, &foreignKey.PublicKey, time.Now().Add(48*time.Hour))
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(leaf)})
	}))
	defer srv.Close()

	d := Deps{
		CAFile:   caPath,
		CertFile: certPath,
		KeyFile:  keyPath,
		PKIURL:   srv.URL,
		Identity: Identity{
			Kind: KindNode,
			CN:   "n-01j9qk3m7x2v5tpb8w4h6n0zya",
			IP:   net.ParseIP("10.0.0.5"),
		},
		Log: discardLog(),
	}

	if err := renewOnce(context.Background(), d, &src); err == nil {
		t.Fatal("сертификат, выданный на чужой ключ, обязан быть отвергнут")
	}

	onDisk, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("чтение файла: %v", err)
	}
	if string(onDisk) != string(staleCert) {
		t.Fatal("отвергнутый сертификат не имеет права лечь на диск поверх старого")
	}
	after, err := src.Get(nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after != before {
		t.Fatal("отвергнутый сертификат не имеет права заменить указатель в памяти")
	}
}
