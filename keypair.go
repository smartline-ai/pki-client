package pkiclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadOrCreateKey возвращает существующий ключ или создаёт новый.
//
// Переиспользование существующего — не оптимизация, а условие корректности
// пути повтора: если нода умерла между тем, как CP погасил токен, и тем, как
// она записала сертификат, вторая попытка обязана предъявить тот же
// публичный ключ. Иначе CP увидит чужой ключ на погашенном токене и откажет.
//
// То же самое верно и внутри одного запуска: если два первых вызова
// стартуют одновременно (гонка при холодном старте), оба пройдут проверку
// "файла нет" и оба сгенерируют СВОИ ключи. На диск ляжет только один — но
// без защиты ниже проигравший вернул бы вызывающему ключ, которого на диске
// уже нет, и разошёлся бы с тем, что реально сохранено. CreateFileExclusive
// гарантирует, что публикация на path происходит ровно один раз; проигравший
// не сочиняет из этого свою ошибку, а читает то, что реально победило.
func LoadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return parseECKey(path, raw)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("pkiclient: чтение %s: %w", path, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pkiclient: генерация ключа: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pkiclient: сериализация ключа: %w", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	if err := CreateFileExclusive(path, body, 0o600); err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("pkiclient: сохранение ключа %s: %w", path, err)
		}
		// Проиграли гонку: между нашим ReadFile и попыткой публикации кто-то
		// другой уже создал path. Наш ключ выбрасывается целиком — он никогда
		// не касался диска — и мы читаем то, что реально там оказалось.
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("pkiclient: чтение %s после проигранной гонки за создание ключа: %w", path, err)
		}
		return parseECKey(path, raw)
	}
	return key, nil
}

func parseECKey(path string, raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("pkiclient: %s не содержит PEM-ключа", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pkiclient: разбор ключа %s: %w", path, err)
	}
	return key, nil
}
