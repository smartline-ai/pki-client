package pkiclient

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic пишет через временный файл в том же каталоге и rename.
// Каталог тот же намеренно: rename атомарен только внутри одной файловой
// системы, а /etc и /tmp на ноде — разные.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("pkiclient: временный файл рядом с %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: режим %s: %w", tmp.Name(), err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: запись %s: %w", tmp.Name(), err)
	}
	// fsync до rename: без него падение машины сразу после переименования
	// оставляет файл нужного имени с нулевым содержимым.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: sync %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pkiclient: закрытие %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("pkiclient: установка %s: %w", path, err)
	}
	return nil
}

// CreateFileExclusive создаёт path и делает это только если его там ещё нет.
// Содержимое сперва целиком пишется и синхронизируется во временный файл
// рядом (та же причина, что у WriteFileAtomic: тот же каталог — та же
// файловая система, только на ней rename и его аналоги атомарны), а затем
// публикуется через os.Link. Link — не rename: он не может незаметно
// подменить уже существующий path, а падает с ошибкой, если тот занят.
//
// Если path уже существует, возвращается ошибка, для которой os.IsExist(err)
// истинен. Она намеренно не оборачивается через fmt.Errorf — обёртка меняет
// динамический тип и ломает os.IsExist для вызывающего, у которого только и
// есть способ понять, что он проиграл гонку с конкурентным первым
// вызывающим, а не столкнулся с чем-то ещё.
func CreateFileExclusive(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("pkiclient: временный файл рядом с %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: режим %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: запись %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: sync %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pkiclient: закрытие %s: %w", tmpPath, err)
	}

	return os.Link(tmpPath, path)
}
