package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/yokedotlol/ns-lol/cli/output"
)

// RunHealth runs a DNS health check. Returns exit code.
func RunHealth(w io.Writer, domain string, opts Options) int {
	return runSignalCheck(w, domain, "health", opts)
}

// RunEmail runs an email security audit. Returns exit code.
func RunEmail(w io.Writer, domain string, opts Options) int {
	return runSignalCheck(w, domain, "email", opts)
}

// RunSecurity runs a DNSSEC & security check. Returns exit code.
func RunSecurity(w io.Writer, domain string, opts Options) int {
	return runSignalCheck(w, domain, "security", opts)
}

func runSignalCheck(w io.Writer, domain, section string, opts Options) int {
	path := "/" + domain + "/" + section

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
		var resp SignalResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return 2
		}
		grade := getGrade(&resp, section)
		if grade != nil && grade.Fail > 0 {
			return 1
		}
		return 0
	}

	if opts.JSON || !isTerminalStdout() {
		return writeRawJSON(w, body)
	}

	var resp SignalResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing response: %v\n", err)
		return 2
	}

	output.PrettySignals(w, &resp, section, opts.NoColor)

	grade := getGrade(&resp, section)
	if grade != nil && grade.Fail > 0 {
		return 1
	}
	return 0
}

func getGrade(resp *SignalResponse, section string) *SignalGrade {
	switch section {
	case "health":
		return resp.Health
	case "email":
		return resp.Email
	case "security":
		return resp.Security
	}
	return nil
}
