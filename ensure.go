package pkiclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Deps — всё, что нужно для получения и поддержания сертификата, без единого
// поля, специфичного для вида участника.
//
// Раньше здесь лежал *config.Config исполнителя целиком, и это была
// единственная причина, по которой пакет нельзя было использовать откуда-то
// ещё. Явные поля вместо него: вызывающий сам решает, из какого своего
// конфига их взять, и модуль не обязан знать форму ни одного из них.
type Deps struct {
	// Mode — ворота. Join пропускается целиком, если это не "control_plane".
	// Именно это защищает работающий демон от выкатки нового кода: бинарь
	// приезжает, а сертификат не трогается, пока переключение не сделают
	// намеренно.
	Mode string

	PKIURL        string
	JoinTokenFile string
	CAFile        string
	CertFile      string
	KeyFile       string

	Identity Identity
	// Extra — полезная нагрузка, осмысленная только для вида node: region,
	// capacity, addresses, agent_version. Пустая карта для service и client.
	// map[string]any, а не структура, потому что модуль не должен знать, что
	// такое ёмкость исполнителя.
	Extra map[string]any

	Log *slog.Logger
	Now func() time.Time
}

// Ensure приводит участника в состояние, где у него есть валидный
// сертификат, либо внятно отказывается стартовать.
//
// Вызывается ДО собственной валидации файлов вызывающего: та обычно жёстко
// падает на отсутствующем сертификате, а отсутствующий сертификат — это
// ровно тот случай, ради которого существует join.
func Ensure(ctx context.Context, d Deps) error {
	// Режим — ворота (§3.2 контракта). В webhook join пропускается целиком,
	// и это то, что защищает работающего участника от выкатки этого кода.
	if d.Mode != "control_plane" {
		d.Log.Info("join пропущен", "mode", d.Mode)
		return nil
	}

	roots, caPEM, err := LoadRoots(d.CAFile)
	if err != nil {
		return fmt.Errorf("%w — прижатый ca.pem обязателен и при join, и при проверке своего сертификата", err)
	}

	// Общий вызов Join для обеих точек, откуда он может понадобиться ниже:
	// обычного отсутствующего/непригодного сертификата и валидного
	// сертификата без ключа. caPEM и roots захвачены из замыкания, чтобы не
	// собирать Params дважды и не дать двум копиям разойтись.
	joinNow := func(token string) error {
		return Join(ctx, Params{
			URL: d.PKIURL, Token: token,
			TokenPath: d.JoinTokenFile,
			Identity:  d.Identity,
			CertPath:  d.CertFile, KeyPath: d.KeyFile,
			CAPEM: caPEM, Roots: roots,
			Extra: d.Extra,
		}, d.Log)
	}

	state, cert, inspectErr := Inspect(d.CertFile, roots, d.Now())
	token, tokenErr := readToken(d.JoinTokenFile)

	if state == CertValid {
		// Валиден сам по себе — не значит пригоден: TLS-хендшейк поднимается
		// на паре, а не на одном файле. os.Stat здесь раньше проверял только
		// то, что файл ключа существует — не то, что он образует пару
		// именно с этим сертификатом. Расколотая пара (валидный сертификат +
		// чужой или отсутствующий ключ) проходила эту проверку неотличимо от
		// целой, и вызывающий падал на tls.LoadX509KeyPair уже после того,
		// как собственная валидация файлов тоже пропустила пару, — без
		// единого шанса на join, даже со свежим токеном рядом (C2 финального
		// ревью). tls.LoadX509KeyPair — не оптимизация поверх os.Stat, это
		// единственный способ узнать, что приватный ключ соответствует
		// открытому ключу в сертификате.
		if _, pairErr := tls.LoadX509KeyPair(d.CertFile, d.KeyFile); pairErr != nil {
			if tokenErr != nil {
				return fmt.Errorf("сертификат %s валиден, но не образует пару с ключом %s (%v), а join-token прочитать не удалось (%v): "+
					"пара расколота, и присоединиться заново нечем", d.CertFile, d.KeyFile, pairErr, tokenErr)
			}
			// LoadOrCreateKey внутри Join создаёт ключ только тогда, когда
			// его нет на диске, и никогда не трогает существующий — так что
			// звать Join здесь не может стереть ключ, от которого зависел бы
			// этот сертификат: раз пара не сходится, зависеть было нечему
			// (ключа нет вовсе, или он уже не тот, что подписан в
			// сертификате). Join выпустит сертификат, согласованный с тем
			// ключом, что реально лежит на диске (или создаст новый, если
			// его нет), и перезапишет осиротевший сертификат.
			d.Log.Warn("сертификат валиден, но не образует пару с ключом — присоединяемся заново",
				"cert", d.CertFile, "key", d.KeyFile, "error", pairErr)
			return joinNow(token)
		}
		if tokenErr == nil {
			d.Log.Warn("рядом с валидным сертификатом лежит неиспользованный join-токен; он не удалён",
				"path", d.JoinTokenFile)
		}
		d.Log.Info("сертификат на месте, join не нужен", "not_after", cert.NotAfter)
		return nil
	}

	// Файл на месте, но прочитать не вышло: под ним мог лежать валидный
	// сертификат. Отказываемся сами, вместо того чтобы по ошибке принять
	// это за CertAbsent и сжечь одноразовый токен на join, который вовсе не
	// был нужен.
	if state == CertUnreadable {
		return fmt.Errorf("сертификат %s есть на диске, но прочитать его не удалось: %w — "+
			"join не запускается, чтобы не сжечь токен вслепую", d.CertFile, inspectErr)
	}

	if tokenErr != nil {
		return fmt.Errorf("сертификат в состоянии %q, а join-token прочитать не удалось (%v): "+
			"присоединиться нечем", state, tokenErr)
	}

	d.Log.Info("присоединяемся к Control Plane", "kind", string(d.Identity.Kind), "cert_state", string(state), "url", d.PKIURL)
	return joinNow(token)
}

func readToken(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("join_token_file не задан")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("%s пуст", path)
	}
	return token, nil
}
