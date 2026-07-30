package pkiclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// CertSource — то, что стоит между файлом на диске и живым TLS-слушателем.
//
// Без него обновление, переписавшее файл, ничего не меняет для процесса,
// поднятого месяцы назад: он продолжит предъявлять старый сертификат прямо
// сквозь дату истечения, и выглядеть это будет как внезапная неспособность CP
// достучаться до очевидно работающего участника.
type CertSource struct {
	cur atomic.Pointer[tls.Certificate]
}

func (s *CertSource) Get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := s.cur.Load()
	if c == nil {
		return nil, fmt.Errorf("pkiclient: сертификат ещё не загружен")
	}
	return c, nil
}

func (s *CertSource) Set(c *tls.Certificate) { s.cur.Store(c) }

// Load читает пару с диска и подменяет указатель. Leaf заполняется явно:
// tls.LoadX509KeyPair его не заполняет, а цикл обновления считает по нему срок.
func (s *CertSource) Load(certPath, keyPath string) error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("pkiclient: загрузка пары %s: %w", certPath, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("pkiclient: разбор листа %s: %w", certPath, err)
	}
	cert.Leaf = leaf
	s.cur.Store(&cert)
	return nil
}

// NeedsRenewal — треть собственного срока сертификата до NotAfter. Срок
// берётся из самого листа, а не из конфига: TTL выбирает CP, и участник
// узнаёт его только по выданному сертификату.
func NeedsRenewal(cert *x509.Certificate, now time.Time) bool {
	if cert == nil {
		return true
	}
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	return now.After(cert.NotAfter.Add(-lifetime / 3))
}

// RunRenewal раз в every проверяет срок и обновляет сертификат.
//
// Час выбран не под точность рубежа, а под то, чтобы участник, простоявший
// выключенным, обнаружил подступающее истечение вскоре после включения, а не
// через сутки.
func RunRenewal(ctx context.Context, d Deps, src *CertSource, every time.Duration) {
	// Те же ворота, что у Ensure (§3.2 контракта, ensure.go). Без них эта
	// горутина безусловно стартовала бы на любом участнике: на dev-1 сегодня
	// это незаметно только потому, что его сертификат живёт 3650 дней и
	// NeedsRenewal никогда не срабатывает, — но участник в webhook или none
	// режиме может не иметь pki_url вовсе, и любой другой с более коротким
	// сертификатом слал бы CSR туда, куда join ему запрещён (финальное
	// ревью, I2).
	if d.Mode != "control_plane" {
		d.Log.Info("обновление сертификата пропущено", "mode", d.Mode)
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			cur, err := src.Get(nil)
			if err != nil {
				continue
			}
			if !NeedsRenewal(cur.Leaf, now) {
				continue
			}
			if err := renewOnce(ctx, d, src); err != nil {
				// Не фатально: текущий сертификат ещё жив целую треть срока,
				// и падать из-за одной неудачи означало бы уронить участника
				// с работающими проектами из-за недоступного на минуту CP.
				d.Log.Error("обновление сертификата не удалось", "error", err)
			}
		}
	}
}

func renewOnce(ctx context.Context, d Deps, src *CertSource) error {
	roots, _, err := LoadRoots(d.CAFile)
	if err != nil {
		return err
	}
	// Ключ переиспользуется: ротация ключа не делается устойчивой к падению
	// при двух отдельных путях в конфиге — падение между переименованием
	// ключа и сертификата оставило бы несовпадающую пару и демон, который не
	// стартует (§6.2 дизайна).
	key, err := LoadOrCreateKey(d.KeyFile)
	if err != nil {
		return err
	}
	csrPEM, err := buildCSR(key, d.Identity)
	if err != nil {
		return err
	}

	cur, err := src.Get(nil)
	if err != nil {
		return err
	}
	hc := &http.Client{
		Timeout: joinHTTPTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      roots,
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{*cur},
		}},
	}

	body, err := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})
	if err != nil {
		return err
	}
	// Обобщённая ручка (control-plane/internal/api/joinrouter.go): kind/cn в
	// пути вместо node_id — единственный маршрут, который обслуживает все
	// три вида без алиаса, поэтому здесь используется он, а не старый
	// /v1/nodes/{node_id}/renew.
	url := d.PKIURL + "/v1/principals/" + string(d.Identity.Kind) + "/" + d.Identity.CN + "/renew"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("pkiclient: обращение к %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pkiclient: обновление отклонено, HTTP %d", resp.StatusCode)
	}

	var out joinResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("pkiclient: ответ обновления не разбирается: %w", err)
	}
	// Та же проверка, что и у join (verifyIssuedCert, join.go), включая
	// совпадение публичного ключа — раньше здесь проверялась только цепочка,
	// и сертификат на чужой ключ лёг бы на диск, оставив узел в состоянии
	// расколотой пары. Обе проверки — до записи на диск: иначе окно между
	// WriteFileAtomic и src.Load могло разойтись с диском на сертификате,
	// для которого ключа нет вообще.
	cert, err := verifyIssuedCert(out.CertPEM, key, roots, d.Identity.Kind)
	if err != nil {
		return fmt.Errorf("pkiclient: обновлённый сертификат не прошёл проверку: %w", err)
	}

	if err := WriteFileAtomic(d.CertFile, []byte(out.CertPEM), 0o644); err != nil {
		return err
	}
	// Файл на диске и указатель в памяти обязаны меняться в этом порядке:
	// иначе падение между ними оставит процесс с сертификатом, которого нет
	// на диске, и следующий старт откатится назад.
	if err := src.Load(d.CertFile, d.KeyFile); err != nil {
		return err
	}
	d.Log.Info("сертификат обновлён", "not_after", cert.NotAfter)
	return nil
}
