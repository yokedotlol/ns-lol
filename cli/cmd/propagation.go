package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/yokedotlol/ns-lol/cli/output"
)

// RunPropagation runs a propagation check. Returns exit code.
func RunPropagation(w io.Writer, domain string, opts Options) int {
	path := "/" + domain + "/propagation"
	if opts.RecordType != "" {
		path += "?type=" + opts.RecordType
	}

	body, status, err := fetchJSON(path, opts.Timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if status >= 400 {
		fmt.Fprintf(os.Stderr, "error: API returned %d\n", status)
		return 2
	}

	if opts.Quiet {
		var resp PropagationResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return 2
		}
		if resp.Propagation.Percentage < 100 {
			return 1
		}
		return 0
	}

	if opts.JSON || !isTerminalStdout() {
		return writeRawJSON(w, body)
	}

	var resp PropagationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing response: %v\n", err)
		return 2
	}

	output.PrettyPropagation(w, &resp, opts.NoColor)
	if resp.Propagation.Percentage < 100 {
		return 1
	}
	return 0
}
