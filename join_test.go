package pkiclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func joinParams(t *testing.T, ca testCA, url, dir string) Params {
	t.Helper()
	return Params{
		URL: url, Token: "тестовый-токен",
		Identity: Identity{
			Kind: KindNode,
			CN:   "n-01j9qk3m7x2v5tpb8w4h6n0zya",
			IP:   net.ParseIP("10.0.0.5"),
		},
		Extra: map[string]any{
			"region":        "fsn1",
			"agent_version": "1.0.0",
			"addresses":     map[string]any{"private_ip": "10.0.0.5"},
			"capacity":      map[string]any{"cpu_millis": int64(2000), "memory_bytes": int64(1 << 32), "disk_bytes": int64(1 << 36)},
		},
		CertPath: filepath.Join(dir, "node.pem"),
		KeyPath:  filepath.Join(dir, "node-key.pem"),
		CAPEM:    ca.pem,
		Roots:    ca.pool(t),
	}
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestJoinWritesCertificateAndDeletesToken(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ca, "", dir)

	// Ключ создаётся до запроса — сервер подпишет именно его.
	key, err := LoadOrCreateKey(p.KeyPath)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("тело запроса не разбирается: %v", err)
		}
		if req["node_id"] != "n-01j9qk3m7x2v5tpb8w4h6n0zya" {
			t.Errorf("node_id = %v", req["node_id"])
		}
		if req["join_token"] != "тестовый-токен" {
			t.Errorf("join_token не доехал")
		}
		leaf := ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(leaf), "ca_pem": string(ca.pem),
		})
	}))
	defer srv.Close()
	p.URL = srv.URL

	tokenPath := filepath.Join(dir, "join-token")
	if err := os.WriteFile(tokenPath, []byte("тестовый-токен"), 0o600); err != nil {
		t.Fatalf("токен: %v", err)
	}
	p.TokenPath = tokenPath

	if err := Join(context.Background(), p, discardLog()); err != nil {
		t.Fatalf("Join: %v", err)
	}

	state, _, _ := Inspect(p.CertPath, ca.pool(t), time.Now())
	if state != CertValid {
		t.Fatalf("после join сертификат в состоянии %q", state)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatal("файл токена обязан быть удалён после успешного join")
	}
}

// Обобщение payload'а (план 03, задача 1, шаг 4): тело join для вида node
// обязано остаться байт-в-байт тем же, что было до обобщения на kind/cn —
// node_id, addresses.private_ip и capacity, — потому что executor-1 будет
// говорить с CP, который тоже обслуживает старый маршрут /v1/nodes/join
// (control-plane/internal/api/joinrouter.go), рассчитанный ровно на эту
// форму тела.
func TestJoinRequestNodeWireFormatUnchanged(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ca, "", dir)
	key, err := LoadOrCreateKey(p.KeyPath)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}

	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("тело запроса не разбирается: %v", err)
			return
		}
		leaf := ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(leaf), "ca_pem": string(ca.pem),
		})
	}))
	defer srv.Close()
	p.URL = srv.URL

	if err := Join(context.Background(), p, discardLog()); err != nil {
		t.Fatalf("Join: %v", err)
	}

	if captured["kind"] != "node" {
		t.Fatalf("kind = %v, ожидалось \"node\"", captured["kind"])
	}
	if captured["cn"] != "n-01j9qk3m7x2v5tpb8w4h6n0zya" {
		t.Fatalf("cn = %v", captured["cn"])
	}
	if captured["node_id"] != "n-01j9qk3m7x2v5tpb8w4h6n0zya" {
		t.Fatalf("node_id = %v, ожидался прежний node_id", captured["node_id"])
	}
	addresses, ok := captured["addresses"].(map[string]any)
	if !ok {
		t.Fatalf("addresses = %v, ожидался объект", captured["addresses"])
	}
	if addresses["private_ip"] != "10.0.0.5" {
		t.Fatalf("addresses.private_ip = %v", addresses["private_ip"])
	}
	capacity, ok := captured["capacity"].(map[string]any)
	if !ok {
		t.Fatalf("capacity = %v, ожидался объект", captured["capacity"])
	}
	if capacity["cpu_millis"] != float64(2000) {
		t.Fatalf("capacity.cpu_millis = %v", capacity["cpu_millis"])
	}
	if captured["region"] != "fsn1" {
		t.Fatalf("region = %v", captured["region"])
	}
	if captured["agent_version"] != "1.0.0" {
		t.Fatalf("agent_version = %v", captured["agent_version"])
	}
}

// Шаг 5 плана: buildCSR собирает три разные формы CSR в зависимости от вида
// участника. Node и service несут ровно один SAN IP — тот, что в Identity;
// client не несёт SAN IP вовсе, что и требует
// control-plane/internal/pki.ValidateCSR для клиентского листа.
func TestBuildCSRPerKind(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}

	cases := []struct {
		name string
		id   Identity
	}{
		{"node несёт SAN IP", Identity{Kind: KindNode, CN: "n-01j9qk3m7x2v5tpb8w4h6n0zya", IP: net.ParseIP("10.0.0.5")}},
		{"service несёт SAN IP", Identity{Kind: KindService, CN: "builder-1", IP: net.ParseIP("10.0.0.9")}},
		{"client не несёт SAN IP", Identity{Kind: KindClient, CN: "ops-laptop", IP: nil}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			csrPEM, err := buildCSR(key, c.id)
			if err != nil {
				t.Fatalf("buildCSR: %v", err)
			}
			block, _ := pem.Decode(csrPEM)
			if block == nil || block.Type != "CERTIFICATE REQUEST" {
				t.Fatal("CSR не PEM")
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatalf("разбор CSR: %v", err)
			}
			if err := csr.CheckSignature(); err != nil {
				t.Fatalf("подпись CSR не сходится: %v", err)
			}
			if csr.Subject.CommonName != c.id.CN {
				t.Fatalf("CN = %q, ожидалось %q", csr.Subject.CommonName, c.id.CN)
			}
			if c.id.IP != nil {
				if len(csr.IPAddresses) != 1 || !csr.IPAddresses[0].Equal(c.id.IP) {
					t.Fatalf("IPAddresses = %v, ожидался ровно [%v]", csr.IPAddresses, c.id.IP)
				}
			} else if len(csr.IPAddresses) != 0 {
				t.Fatalf("IPAddresses = %v, client не имеет права нести SAN IP", csr.IPAddresses)
			}
		})
	}
}

// 4xx фатален: отвергнутый токен не станет принятым от повторов, а демон,
// который их делает, прячет ошибку провижининга за зелёным юнитом.
func TestJoinFatalOn4xx(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"code":"join_denied","message":"нет","details":{}}}`))
	}))
	defer srv.Close()

	p := joinParams(t, ca, srv.URL, dir)
	if _, err := LoadOrCreateKey(p.KeyPath); err != nil {
		t.Fatalf("ключ: %v", err)
	}
	err := Join(context.Background(), p, discardLog())
	if !errors.Is(err, ErrJoinRejected) {
		t.Fatalf("err = %v, ожидалась ErrJoinRejected", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("сделано %d попыток, 4xx не должен повторяться", calls.Load())
	}
}

func TestJoinRetriesOn5xx(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ca, "", dir)
	key, _ := LoadOrCreateKey(p.KeyPath)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		leaf := ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(leaf), "ca_pem": string(ca.pem)})
	}))
	defer srv.Close()
	p.URL = srv.URL
	p.Backoff = time.Millisecond // тест не должен ждать секундами

	if err := Join(context.Background(), p, discardLog()); err != nil {
		t.Fatalf("Join: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("попыток %d, ожидалось 3", calls.Load())
	}
}

// Сертификат, не собирающийся в цепочку к прижатому CA, не имеет права лечь
// на диск: иначе подменённый CP навязал бы участнику свою идентичность.
func TestJoinRejectsCertificateFromForeignCA(t *testing.T) {
	ours := makeCA(t)
	foreign := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ours, "", dir)
	key, _ := LoadOrCreateKey(p.KeyPath)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaf := foreign.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(leaf), "ca_pem": string(foreign.pem)})
	}))
	defer srv.Close()
	p.URL = srv.URL

	if err := Join(context.Background(), p, discardLog()); err == nil {
		t.Fatal("сертификат от чужого CA обязан быть отвергнут")
	}
	if _, err := os.Stat(p.CertPath); !os.IsNotExist(err) {
		t.Fatal("отвергнутый сертификат не имеет права лечь на диск")
	}
}

// Сертификат может честно собираться в цепочку к прижатому CA и всё равно
// быть непригодным: если он выдан на чужой публичный ключ, у участника нет
// приватного ключа к нему, и TLS-хендшейк никогда не поднимется. Эта ветка
// installCert отдельная от проверки цепочки (TestJoinRejectsCertificateFromForeignCA).
func TestJoinRejectsCertificateOnForeignKey(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ca, "", dir)
	if _, err := LoadOrCreateKey(p.KeyPath); err != nil {
		t.Fatalf("ключ: %v", err)
	}

	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("чужой ключ: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Верный CA (ca), но подписан на ключ, которого у участника нет.
		leaf := ca.leafFor(t, &foreignKey.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(leaf), "ca_pem": string(ca.pem)})
	}))
	defer srv.Close()
	p.URL = srv.URL

	if err := Join(context.Background(), p, discardLog()); err == nil {
		t.Fatal("сертификат, выданный на чужой ключ, обязан быть отвергнут")
	}
	if _, err := os.Stat(p.CertPath); !os.IsNotExist(err) {
		t.Fatal("отвергнутый сертификат не имеет права лечь на диск, даже если цепочка к CA верна")
	}
}
