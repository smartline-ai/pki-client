package pkiclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"time"
)

// ErrJoinRejected — отказ, который не станет успехом от повторов: неверный
// токен, кривой CSR, чужой CN.
var ErrJoinRejected = errors.New("pkiclient: Control Plane отклонил присоединение")

const (
	joinTimeout     = 10 * time.Minute
	joinBackoffCap  = 30 * time.Second
	joinHTTPTimeout = 30 * time.Second
)

// Params — все входные данные для одного join.
//
// Раньше здесь лежали NodeID/Region/AgentVersion/Addresses/Capacity — поля,
// осмысленные только для вида node. Теперь то, что уходит в CSR (CN, IP),
// несёт Identity, а всё остальное, что имеет смысл лишь для конкретного
// вида, — Extra: она разворачивается в те же ключи верхнего уровня тела
// запроса, какими были region/addresses/capacity/agent_version до
// обобщения.
type Params struct {
	URL       string
	Token     string
	TokenPath string
	Identity  Identity
	CertPath  string
	KeyPath   string
	CAPEM     []byte
	Roots     *x509.CertPool
	// Extra — полезная нагрузка, осмысленная только для вида node: region,
	// capacity, addresses, agent_version. Пустая карта для service и client.
	Extra map[string]any
	// Backoff — начальная пауза между попытками. Ноль означает секунду; в
	// тестах ставится в миллисекунды, чтобы не ждать по-настоящему.
	Backoff time.Duration
}

// joinRequest — тело POST /v1/principals/join.
type joinRequest struct {
	JoinToken string
	Kind      string
	CN        string
	CSRPEM    string
	// NodeID сохранён для вида node: старая ручка /v1/nodes/join читает
	// именно его, и она остаётся живой на весь период переключения (план
	// 02, задача 5; control-plane/internal/api/joinrouter.go). Для
	// service/client не заполняется.
	NodeID string
	Extra  map[string]any
}

// MarshalJSON собирает join_token/kind/cn/csr_pem[/node_id] и разворачивает
// Extra в те же ключи верхнего уровня. Так тело join для вида node остаётся
// байт-в-байт тем же, что было до обобщения — node_id, addresses.private_ip,
// capacity, region, agent_version, — а у service/client лишних полей просто
// нет, потому что их Extra пуст.
func (r joinRequest) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(r.Extra)+5)
	for k, v := range r.Extra {
		m[k] = v
	}
	m["join_token"] = r.JoinToken
	m["kind"] = r.Kind
	m["cn"] = r.CN
	m["csr_pem"] = r.CSRPEM
	if r.NodeID != "" {
		m["node_id"] = r.NodeID
	}
	return json.Marshal(m)
}

type joinResponse struct {
	CertPEM string `json:"cert_pem"`
	CAPEM   string `json:"ca_pem"`
}

// Join выполняет присоединение целиком: ключ уже на диске (его положил
// вызывающий), отсюда уходит CSR и сюда возвращается сертификат.
func Join(ctx context.Context, p Params, log *slog.Logger) error {
	key, err := LoadOrCreateKey(p.KeyPath)
	if err != nil {
		return err
	}
	csrPEM, err := buildCSR(key, p.Identity)
	if err != nil {
		return err
	}

	hc := &http.Client{
		Timeout: joinHTTPTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    p.Roots,
			MinVersion: tls.VersionTLS13,
		}},
	}

	// node_id заполняется только для вида node: старая ручка читает именно
	// его, а CN для этого вида и есть node_id (design §11).
	var nodeID string
	if p.Identity.Kind == KindNode {
		nodeID = p.Identity.CN
	}
	body, err := json.Marshal(joinRequest{
		JoinToken: p.Token, Kind: string(p.Identity.Kind), CN: p.Identity.CN,
		CSRPEM: string(csrPEM), NodeID: nodeID, Extra: p.Extra,
	})
	if err != nil {
		return fmt.Errorf("pkiclient: сборка тела join: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, joinTimeout)
	defer cancel()

	backoff := p.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	for attempt := 0; ; attempt++ {
		resp, err := postJoin(ctx, hc, p.URL+"/v1/principals/join", body)
		if err == nil {
			return installCert(p, key, resp, log)
		}
		if errors.Is(err, ErrJoinRejected) {
			return err
		}
		if ctx.Err() != nil {
			return fmt.Errorf("pkiclient: join не удался за %s: %w", joinTimeout, err)
		}
		wait := time.Duration(math.Min(
			float64(backoff)*math.Pow(2, float64(attempt)),
			float64(joinBackoffCap)))
		log.Warn("join не удался, повтор", "attempt", attempt+1, "wait", wait, "error", err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("pkiclient: join не удался за %s: %w", joinTimeout, err)
		case <-time.After(wait):
		}
	}
}

func postJoin(ctx context.Context, hc *http.Client, url string, body []byte) (*joinResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("pkiclient: запрос join: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pkiclient: обращение к %s: %w", url, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// Тело не цитируется: в нём нет ничего, чего нет в коде, а токен в
		// журнале не нужен.
		return nil, fmt.Errorf("%w: HTTP %d", ErrJoinRejected, resp.StatusCode)
	default:
		return nil, fmt.Errorf("pkiclient: Control Plane ответил HTTP %d", resp.StatusCode)
	}

	var out joinResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("pkiclient: ответ join не разбирается: %w", err)
	}
	if out.CertPEM == "" {
		return nil, fmt.Errorf("pkiclient: ответ join без cert_pem")
	}
	return &out, nil
}

// installCert проверяет выданный сертификат до того, как он ляжет на диск.
func installCert(p Params, key *ecdsa.PrivateKey, resp *joinResponse, log *slog.Logger) error {
	cert, err := verifyIssuedCert(resp.CertPEM, key, p.Roots)
	if err != nil {
		return fmt.Errorf("pkiclient: %w", err)
	}

	if err := WriteFileAtomic(p.CertPath, []byte(resp.CertPEM), 0o644); err != nil {
		return err
	}
	// Токен удаляется только теперь: до этой точки повтор ещё имеет смысл.
	if p.TokenPath != "" {
		if err := os.Remove(p.TokenPath); err != nil && !os.IsNotExist(err) {
			log.Warn("файл токена не удалён", "path", p.TokenPath, "error", err)
		}
	}
	log.Info("участник присоединился", "kind", string(p.Identity.Kind), "cn", p.Identity.CN, "not_after", cert.NotAfter)
	return nil
}

// verifyIssuedCert разбирает и проверяет сертификат, пришедший от Control
// Plane, до того как он коснётся диска. Общая для join (installCert) и
// renew (renewOnce): до одного из предыдущих ревью копии успели разойтись —
// у renew не было проверки публичного ключа вовсе, и это позволяло
// сертификату, выданному не на тот ключ, лечь на диск, оставив узел в
// состоянии расколотой пары.
//
// Проверок две, и обе обязательны: цепочка к прижатому CA — против
// подменённого Control Plane, совпадение публичного ключа — против
// сертификата, к которому у нас нет приватного ключа.
func verifyIssuedCert(certPEM string, key *ecdsa.PrivateKey, roots *x509.CertPool) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("cert_pem не разбирается")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("разбор выданного сертификата: %w", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, fmt.Errorf("выданный сертификат не собирается в цепочку к прижатому CA: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("выдан сертификат на чужой ключ")
	}
	return cert, nil
}

// buildCSR собирает CSR для конкретного вида участника. CN — всегда id.CN;
// IPAddresses выставляется только когда id.IP != nil. У client IP всегда
// nil, и CSR остаётся без SAN IP вовсе — это то, что требует
// control-plane/internal/pki.ValidateCSR для клиентского листа (пустой
// IPAddresses, иначе отказ).
func buildCSR(key *ecdsa.PrivateKey, id Identity) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: id.CN},
		DNSNames:           []string{id.CN},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	if id.IP != nil {
		tmpl.IPAddresses = []net.IP{id.IP}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("pkiclient: создание CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
