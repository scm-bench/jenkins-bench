package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

// writePrivate writes data to path with mode 0600, atomically.
//
// Reports and snapshots describe a controller's weak points — which jobs run
// unsandboxed Groovy, which can be started with a token — so they are kept to
// the account that wrote them. os.WriteFile applies its mode only when it
// creates a file: a snapshot written over an existing 0644 one stayed
// world-readable. So the data goes to a temporary file in the same directory,
// created 0600 (and chmod'ed to it, against an unusual umask), and is renamed
// over the destination: whatever was there is replaced whole, with these
// permissions, and a write that fails half-way leaves the old file intact
// rather than a truncated one that looks complete.
func writePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	committed = true
	return nil
}
