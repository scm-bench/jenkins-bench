package report

import (
	"encoding/json"
	"io"

	"github.com/scm-bench/jenkins-bench/internal/engine"
)

// writeJSON emits the report as it stands.
func writeJSON(w io.Writer, rep *engine.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Findings carry remediation text with paths like "Settings -> Hooks";
	// escaping those into > would make the output unreadable.
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}
