package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// createTemp is os.CreateTemp; a variable so a test can hand writePrivate a
// file that refuses writes, the way a full disk does.
var createTemp = os.CreateTemp

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
	tmp, err := createTemp(dir, "."+filepath.Base(path)+".*.tmp")
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
	// Each step runs even if an earlier one failed — harmless, since a
	// failure means the temporary file is removed rather than renamed — so
	// every reason it failed is reported together.
	chmodErr := tmp.Chmod(0o600)
	_, writeErr := tmp.Write(data)
	if err := errors.Join(chmodErr, writeErr, tmp.Sync(), tmp.Close()); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	committed = true
	return nil
}
