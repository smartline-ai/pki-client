package pkiclient

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// CertState — то, что лежит на диске, с точки зрения решения «присоединяться
// или нет». Строка, а не int: она попадает в журнал, и "foreign_ca" читается
// лучше, чем "3".
type CertState string

const (
	CertAbsent      CertState = "absent"
	CertUnreadable  CertState = "unreadable"
	CertUnparseable CertState = "unparseable"
	CertExpired     CertState = "expired"
	CertForeignCA   CertState = "foreign_ca"
	CertValid       CertState = "valid"
)

// LoadRoots читает прижатый CA. Он обязателен всегда: без него нода не может
// ни проверить Control Plane при join, ни понять, свой ли сертификат у неё на
// диске.
func LoadRoots(caPath string) (*x509.CertPool, []byte, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, fmt.Errorf("pkiclient: чтение CA %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("pkiclient: %s не содержит сертификатов", caPath)
	}
	return pool, caPEM, nil
}

// Inspect классифицирует сертификат. Порядок проверок важен: просроченный
// сертификат от своего CA и валидный от чужого — разные истории, и в журнале
// они обязаны выглядеть по-разному, иначе диагностика упирается в "TLS не
// работает".
//
// CertAbsent и CertUnreadable — тоже разные истории, хоть обе и означают "нет
// сертификата, который можно предъявить". CertAbsent — файла на диске нет,
// join уместен. CertUnreadable — файл есть, но прочитать его не удалось
// (права, это каталог, диск отвалился); здесь могло лежать валидное
// удостоверение, и вызывающий обязан отказаться сам, а не тихо решить, что
// join безопасен. Третий элемент возврата ненулевой только для
// CertUnreadable и несёт исходную ошибку чтения.
func Inspect(certPath string, roots *x509.CertPool, now time.Time) (CertState, *x509.Certificate, error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return CertAbsent, nil, nil
		}
		return CertUnreadable, nil, fmt.Errorf("pkiclient: чтение сертификата %s: %w", certPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return CertUnparseable, nil, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertUnparseable, nil, nil
	}
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		return CertExpired, cert, nil
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return CertForeignCA, cert, nil
	}
	return CertValid, cert, nil
}
