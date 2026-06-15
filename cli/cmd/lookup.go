package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/yokedotlol/ns-lol/cli/api"
	"github.com/yokedotlol/ns-lol/cli/output"
)

// RunLookup performs a full DNS lookup and writes output. Returns exit code.
func RunLookup(w io.Writer, domain string, opts Options) int {
	path := "/" + domain
	if opts.RecordType != "" {
		path += "/" + opts.RecordType
	}

	body, status, err := api.FetchJSON(path, opts.Timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if status >= 400 {
		fmt.Fprintf(os.Stderr, "error: API returned %d\n", status)
		if len(body) > 0 {
			os.Stderr.Write(body)
			os.Stderr.Write([]byte("\n"))
		}
		return 2
	}

	if opts.Quiet {
		return 0
	}

	if opts.JSON || !isTerminalStdout() {
		return writeRawJSON(w, body)
	}

	// Single record-type queries return a flat records array.
	// Full lookups return records as map[type]section.
	if opts.RecordType != "" {
		var resp api.SingleLookupResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: parsing response: %v\n", err)
			return 2
		}
		output.PrettySingleLookup(w, &resp, opts.NoColor)
		return 0
	}

	var resp api.LookupResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing response: %v\n", err)
		return 2
	}

	output.PrettyLookup(w, &resp, opts.NoColor)
	return 0
}

func isTerminalStdout() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func writeRawJSON(w io.Writer, data []byte) int {
	if err := api.PrintRawJSON(w, data); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	return 0
}
