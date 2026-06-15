package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/yokedotlol/ns-lol/cli/output"
)

// RunCompare performs a side-by-side DNS comparison. Returns exit code.
func RunCompare(w io.Writer, domainA, domainB string, opts Options) int {
	bodyA, statusA, errA := fetchJSON("/"+domainA, opts.Timeout)
	bodyB, statusB, errB := fetchJSON("/"+domainB, opts.Timeout)

	if errA != nil {
		fmt.Fprintf(os.Stderr, "error fetching %s: %v\n", domainA, errA)
		return 2
	}
	if errB != nil {
		fmt.Fprintf(os.Stderr, "error fetching %s: %v\n", domainB, errB)
		return 2
	}
	if statusA >= 400 {
		fmt.Fprintf(os.Stderr, "error: API returned %d for %s\n", statusA, domainA)
		return 2
	}
	if statusB >= 400 {
		fmt.Fprintf(os.Stderr, "error: API returned %d for %s\n", statusB, domainB)
		return 2
	}

	if opts.JSON || !isTerminalStdout() {
		_ = printRawJSON(w, bodyA)
		_ = printRawJSON(w, bodyB)
		return 0
	}

	var respA, respB LookupResponse
	if err := json.Unmarshal(bodyA, &respA); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing response for %s: %v\n", domainA, err)
		return 2
	}
	if err := json.Unmarshal(bodyB, &respB); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing response for %s: %v\n", domainB, err)
		return 2
	}

	output.PrettyCompare(w, &respA, &respB, opts.NoColor)
	return 0
}
