package pkiclient

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes through a temporary file in the same directory and
// renames. The same directory is deliberate: rename is atomic only within one
// filesystem, and /etc and /tmp on a node are different ones.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("pkiclient: temporary file next to %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: mode of %s: %w", tmp.Name(), err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: writing %s: %w", tmp.Name(), err)
	}
	// fsync before rename: without it a machine crash right after the rename
	// leaves a file with the right name and zero contents.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: sync %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pkiclient: closing %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("pkiclient: installing %s: %w", path, err)
	}
	return nil
}

// CreateFileExclusive creates path, and does so only if it is not there yet.
// The contents are first written and synced in full to a temporary file next
// to it (same reason as in WriteFileAtomic: same directory means same
// filesystem, and only there are rename and its relatives atomic), and then
// published via os.Link. Link is not rename: it cannot silently replace an
// already existing path, it fails if that path is taken.
//
// If path already exists, the returned error is one for which os.IsExist(err)
// is true. It is deliberately not wrapped with fmt.Errorf — wrapping changes
// the dynamic type and breaks os.IsExist for the caller, whose only way to
// tell that it lost the race to a concurrent first caller (rather than hit
// something else) is exactly that check.
func CreateFileExclusive(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("pkiclient: temporary file next to %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: mode of %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: writing %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("pkiclient: sync %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pkiclient: closing %s: %w", tmpPath, err)
	}

	return os.Link(tmpPath, path)
}
