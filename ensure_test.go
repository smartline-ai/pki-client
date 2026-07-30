package pkiclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ensureDeps(t *testing.T, dir, mode string) Deps {
	t.Helper()
	return Deps{
		Mode:          mode,
		PKIURL:        "https://10.0.0.3:8444",
		JoinTokenFile: filepath.Join(dir, "join-token"),
		CAFile:        filepath.Join(dir, "ca.pem"),
		CertFile:      filepath.Join(dir, "node.pem"),
		KeyFile:       filepath.Join(dir, "node-key.pem"),
		Identity: Identity{
			Kind: KindNode,
			CN:   "n-01j9qk3m7x2v5tpb8w4h6n0zya",
			IP:   net.ParseIP("10.0.0.5"),
		},
		Extra: map[string]any{
			"region":        "fsn1",
			"agent_version": "1.0.0",
			"addresses":     map[string]any{"private_ip": "10.0.0.5"},
		},
		Log: discardLog(),
		Now: time.Now,
	}
}

func TestEnsureSkipsInWebhookMode(t *testing.T) {
	dir := t.TempDir()
	d := ensureDeps(t, dir, "webhook")
	// Ни CA, ни сертификата, ни токена — и всё равно никакой ошибки:
	// в режиме webhook join пропускается целиком (§3.2 контракта), и
	// работающий участник на dev-1 обязан пережить выкатку этого кода.
	if err := Ensure(context.Background(), d); err != nil {
		t.Fatalf("в режиме webhook Ensure обязан быть no-op, получено: %v", err)
	}
}

func TestEnsureRequiresCAAlways(t *testing.T) {
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	err := Ensure(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "ca.pem") {
		t.Fatalf("отсутствие прижатого CA обязано валить старт с упоминанием файла, получено: %v", err)
	}
}

func TestEnsureSkipsWhenCertificateValid(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	// Ключ — полноправная половина идентичности: без него один сертификат не
	// повод пропускать join (см. TestEnsureRejoinsWhenValidCertificateHasNoKey).
	// Ключ создаётся ДО сертификата и сертификат подписывается именно на его
	// публичную часть (leafFor, а не leaf) — иначе пара на диске расколота по
	// построению теста, и с введённой проверкой (C2) Ensure законно уходит в
	// join вместо пропуска, чего этот тест как раз не хочет проверять.
	key, err := LoadOrCreateKey(d.KeyFile)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	writeFile(t, d.CertFile, ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour)))
	// Токен лежит рядом и обязан ПЕРЕЖИТЬ вызов: молча уничтожать
	// удостоверение, положенное для планового повторного присоединения, хуже,
	// чем оставить его.
	writeFile(t, d.JoinTokenFile, []byte("не-трогать"))

	if err := Ensure(context.Background(), d); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if _, err := os.Stat(d.JoinTokenFile); err != nil {
		t.Fatal("токен рядом с валидным сертификатом не имеет права быть удалённым")
	}
}

// Сертификат валиден сам по себе, но без ключа он не идентичность: TLS не
// поднимется без приватного ключа. Раз есть чем присоединиться (токен на
// месте), Ensure обязан заметить расколотую пару и присоединиться заново,
// вместо того чтобы принять один валидный на вид файл за готовую идентичность
// и молча разрешить запуск — именно так воспроизводился баг из ревью.
func TestEnsureRejoinsWhenValidCertificateHasNoKey(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	staleCert := ca.leaf(t, time.Now().Add(time.Hour))
	writeFile(t, d.CertFile, staleCert)
	// Ключ умышленно не создан: сертификат есть, ключа к нему нет.
	writeFile(t, d.JoinTokenFile, []byte("тестовый-токен"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("тело запроса не разбирается: %v", err)
			return
		}
		csrPEM, _ := req["csr_pem"].(string)
		block, _ := pem.Decode([]byte(csrPEM))
		if block == nil {
			t.Errorf("csr_pem не PEM")
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Errorf("csr_pem не разбирается: %v", err)
			return
		}
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Errorf("CSR не на EC-ключе")
			return
		}
		leaf := ca.leafFor(t, pub, time.Now().Add(time.Hour))
		if err := json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(leaf), "ca_pem": string(ca.pem),
		}); err != nil {
			t.Errorf("ответ join не пишется: %v", err)
		}
	}))
	defer srv.Close()
	d.PKIURL = srv.URL

	if err := Ensure(context.Background(), d); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if _, err := os.Stat(d.KeyFile); err != nil {
		t.Fatal("отсутствовавший ключ обязан быть создан присоединением заново")
	}
	newCert, err := os.ReadFile(d.CertFile)
	if err != nil {
		t.Fatalf("чтение нового сертификата: %v", err)
	}
	if string(newCert) == string(staleCert) {
		t.Fatal("осиротевший сертификат обязан быть перезаписан новым, согласованным с ключом")
	}
	if _, err := os.Stat(d.JoinTokenFile); !os.IsNotExist(err) {
		t.Fatal("токен обязан быть удалён после успешного присоединения заново")
	}
}

// Прямая репродукция C2 финального ревью: сертификат валиден сам по себе, а
// на диске лежит ключ, который ему не принадлежит (например — join когда-то
// упал между записью нового ключа и получением нового сертификата, оставив
// старый сертификат рядом с новым ключом). Раньше эту пару пропускал
// os.Stat, потому что оба файла существовали; демон стартовал бы дальше и
// падал уже на tls.LoadX509KeyPair у вызывающего, без единого шанса на join,
// даже со свежим токеном рядом. Ensure обязан заметить несовпадение и
// присоединиться заново, переиспользуя лежащий на диске ключ (а не отбрасывая
// его) — именно так, как это делает путь повтора §6.1.1: Join увидит
// существующий файл ключа и подпишет CSR им же.
func TestEnsureRejoinsWhenCertificateAndKeyAreMismatched(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	staleCert := ca.leaf(t, time.Now().Add(time.Hour))
	writeFile(t, d.CertFile, staleCert)
	// Ключ на диске реален и читаем, но подписан не для этого сертификата.
	mismatchedKey, err := LoadOrCreateKey(d.KeyFile)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	writeFile(t, d.JoinTokenFile, []byte("тестовый-токен"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("тело запроса не разбирается: %v", err)
			return
		}
		csrPEM, _ := req["csr_pem"].(string)
		block, _ := pem.Decode([]byte(csrPEM))
		if block == nil {
			t.Errorf("csr_pem не PEM")
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Errorf("csr_pem не разбирается: %v", err)
			return
		}
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Errorf("CSR не на EC-ключе")
			return
		}
		// Подтверждаем, что CSR несёт ключ, УЖЕ лежавший на диске, а не
		// какой-то новый: путь повтора обязан переиспользовать его.
		if !pub.Equal(&mismatchedKey.PublicKey) {
			t.Errorf("CSR подписан не тем ключом, что уже лежал на диске")
		}
		leaf := ca.leafFor(t, pub, time.Now().Add(time.Hour))
		if err := json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(leaf), "ca_pem": string(ca.pem),
		}); err != nil {
			t.Errorf("ответ join не пишется: %v", err)
		}
	}))
	defer srv.Close()
	d.PKIURL = srv.URL

	if err := Ensure(context.Background(), d); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	newCert, err := os.ReadFile(d.CertFile)
	if err != nil {
		t.Fatalf("чтение нового сертификата: %v", err)
	}
	if string(newCert) == string(staleCert) {
		t.Fatal("расколотая пара обязана быть исправлена новым сертификатом")
	}
	// Ключ на диске не должен был замениться: LoadOrCreateKey не трогает
	// существующий файл, и пара чинится со стороны сертификата.
	keyOnDisk, err := os.ReadFile(d.KeyFile)
	if err != nil {
		t.Fatalf("чтение ключа: %v", err)
	}
	stillSameKey, err := parseECKey(d.KeyFile, keyOnDisk)
	if err != nil {
		t.Fatalf("разбор ключа: %v", err)
	}
	if !stillSameKey.PublicKey.Equal(&mismatchedKey.PublicKey) {
		t.Fatal("ключ на диске обязан остаться тем же самым — исправляется только сертификат")
	}
	if _, err := os.Stat(d.JoinTokenFile); !os.IsNotExist(err) {
		t.Fatal("токен обязан быть удалён после успешного присоединения заново")
	}
	// И главное — итоговая пара обязана реально совпадать: это тот факт,
	// который раньше проверял только os.Stat, и который прежде принял бы
	// эту самую комбинацию файлов как валидную идентичность.
	if _, err := tls.LoadX509KeyPair(d.CertFile, d.KeyFile); err != nil {
		t.Fatalf("итоговая пара не сходится: %v", err)
	}
}

// Тот же расколотый случай (сертификат валиден, ключа нет), но без токена
// присоединиться заново нечем — Ensure обязан отказаться внятно, и сообщение
// обязано назвать именно отсутствующий файл (ключ), а не рассуждать про
// сертификат, который на самом деле на месте. Ensure также не имеет права
// создать сиротский ключ, когда пара всё равно не может быть восстановлена.
func TestEnsureFailsWhenValidCertificateHasNoKeyAndNoToken(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	writeFile(t, d.CertFile, ca.leaf(t, time.Now().Add(time.Hour)))
	// Ни ключа, ни токена.

	err := Ensure(context.Background(), d)
	if err == nil {
		t.Fatal("валидный сертификат без ключа и без токена обязан провалить Ensure")
	}
	if !strings.Contains(err.Error(), d.KeyFile) {
		t.Fatalf("ошибка обязана называть отсутствующий файл ключа, получено: %v", err)
	}
	if _, statErr := os.Stat(d.KeyFile); !os.IsNotExist(statErr) {
		t.Fatal("Ensure не имеет права создать ключ, когда присоединиться заново нечем")
	}
}

func TestEnsureFailsWithoutCertificateAndWithoutToken(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)

	err := Ensure(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "join-token") {
		t.Fatalf("нет сертификата и нет токена — обязан быть внятный отказ, получено: %v", err)
	}
}

func TestEnsureReportsExpiredDistinctlyFromAbsent(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	writeFile(t, d.CertFile, ca.leaf(t, time.Now().Add(-time.Minute)))

	err := Ensure(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("просроченный сертификат без токена обязан назваться просроченным, получено: %v", err)
	}
}

// Нечитаемый сертификат — не то же самое, что отсутствующий: под ним может
// лежать валидное удостоверение. Ensure обязан отказаться сам и НЕ трогать
// join, иначе он рискует сжечь единственный одноразовый токен на
// присоединение, которое было не нужно. Каталог на месте файла сертификата
// даёт ошибку чтения, которая не является os.ErrNotExist.
func TestEnsureFailsClosedWhenCertificateUnreadable(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	if err := os.Mkdir(d.CertFile, 0o755); err != nil {
		t.Fatalf("каталог вместо файла сертификата: %v", err)
	}
	writeFile(t, d.JoinTokenFile, []byte("не-трогать"))

	err := Ensure(context.Background(), d)
	if err == nil {
		t.Fatal("нечитаемый сертификат обязан провалить Ensure, а не тихо запустить join")
	}
	if strings.Contains(err.Error(), "join-token") {
		t.Fatalf("ошибка не имеет права звучать как отсутствие токена, получено: %v", err)
	}
	if _, statErr := os.Stat(d.JoinTokenFile); statErr != nil {
		t.Fatal("токен не имеет права быть тронутым, пока Join не вызывался")
	}
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("запись %s: %v", path, err)
	}
}
