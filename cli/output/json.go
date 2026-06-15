package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// JSONMeta holds metadata about the CLI invocation.
type JSONMeta struct {
	Source    string `json:"source"`
	Version  string `json:"version"`
	Timestamp string `json:"timestamp"`
}

// JSONOutput wraps any API response with CLI metadata.
type JSONOutput struct {
	Data interface{} `json:"data"`
	Meta JSONMeta    `json:"_meta"`
}

// JSON writes machine-readable JSON output, wrapping API data with CLI metadata.
func JSON(w io.Writer, data interface{}, version string) error {
	out := JSONOutput{
		Data: data,
		Meta: JSONMeta{
			Source:    "cli",
			Version:  version,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("json encode: %w", err)
	}
	return nil
}
