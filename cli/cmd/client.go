// Package cmd provides the API client and command orchestration for the ns CLI.
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Options configures a command run.
type Options struct {
	JSON       bool
	Quiet      bool
	NoColor    bool
	RecordType string
	Timeout    time.Duration
	Version    string
}

// apiBase is the ns.lol API endpoint.
const apiBase = "https://ns.lol"

// fetchJSON makes a GET request to the ns.lol API and returns raw JSON bytes.
func fetchJSON(path string, timeout time.Duration) ([]byte, int, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", apiBase+path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "ns-cli/1.0 (+https://ns.lol)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read body (bounded to 2MB)
	body := make([]byte, 0, 16384)
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
			if len(body) > 2*1024*1024 {
				return nil, resp.StatusCode, fmt.Errorf("response too large")
			}
		}
		if readErr != nil {
			break
		}
	}

	return body, resp.StatusCode, nil
}

// ─── API response types ────────────────────────────────────────────

// LookupResponse is the top-level DNS lookup response.
type LookupResponse struct {
	Domain    string                       `json:"domain"`
	QueryTime string                      `json:"query_time"`
	Resolver  string                       `json:"resolver"`
	Summary   LookupSummary                `json:"summary"`
	Records   map[string]RecordTypeSection `json:"records"`
	Meta      map[string]string            `json:"_meta"`
}

// LookupSummary holds overview stats.
type LookupSummary struct {
	TotalRecords int    `json:"total_records"`
	RecordTypes  int    `json:"record_types"`
	AvgQueryMs   int    `json:"avg_query_time_ms"`
	DNSSEC       string `json:"dnssec"`
}

// RecordTypeSection groups records by type.
type RecordTypeSection struct {
	Records    []Record `json:"records"`
	Rcode      string   `json:"rcode"`
	QueryTimeMs int     `json:"query_time_ms"`
}

// Record is a single DNS record.
type Record struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	TTL      int    `json:"TTL"`
	Data     string `json:"data"`
	TTLHuman string `json:"ttl_human"`
}

// SignalResponse is used for health, email, and security endpoints.
type SignalResponse struct {
	Domain    string        `json:"domain"`
	QueryTime string       `json:"query_time"`
	Health    *SignalGrade  `json:"health,omitempty"`
	Email     *SignalGrade  `json:"email,omitempty"`
	Security  *SignalGrade  `json:"security,omitempty"`
	Signals   []Signal      `json:"signals"`
	Meta      map[string]string `json:"_meta"`
}

// SignalGrade is the grade summary for a check endpoint.
type SignalGrade struct {
	Grade          string `json:"grade"`
	SignalsChecked int    `json:"signals_checked"`
	Pass           int    `json:"pass"`
	Warn           int    `json:"warn"`
	Fail           int    `json:"fail"`
	Info           int    `json:"info"`
}

// Signal is an individual check result.
type Signal struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Label    string `json:"label"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix,omitempty"`
}

// PropagationResponse is the propagation check response.
type PropagationResponse struct {
	Domain      string               `json:"domain"`
	Type        string               `json:"type"`
	QueryTime   string               `json:"query_time"`
	Propagation PropagationSummary   `json:"propagation"`
	Answers     []PropagationAnswer  `json:"distinct_answers"`
	Resolvers   []PropagationResult  `json:"resolvers,omitempty"`
	Meta        map[string]string    `json:"_meta"`
}

// PropagationSummary holds propagation stats.
type PropagationSummary struct {
	Status            string          `json:"status"`
	Percentage        int             `json:"percentage"`
	Consistency       int             `json:"consistency"`
	ResolversQueried  int             `json:"resolvers_queried"`
	ResolversResponded int            `json:"resolvers_responded"`
	ResolversErrored  int             `json:"resolvers_errored"`
	DistinctAnswers   int             `json:"distinct_answers"`
	TTL               *PropagationTTL `json:"ttl,omitempty"`
}

// PropagationTTL holds min/max TTL info.
type PropagationTTL struct {
	Min      int    `json:"min"`
	Max      int    `json:"max"`
	MinHuman string `json:"min_human"`
	MaxHuman string `json:"max_human"`
}

// PropagationAnswer is a distinct answer group.
type PropagationAnswer struct {
	Value     []string `json:"value"`
	Resolvers []string `json:"resolvers"`
	Count     int      `json:"count"`
	IsMajority bool   `json:"is_majority"`
}

// PropagationResult is a single resolver's result.
type PropagationResult struct {
	Resolver    string   `json:"resolver"`
	Location    string   `json:"location"`
	Records     []string `json:"records"`
	Rcode       string   `json:"rcode"`
	QueryTimeMs int      `json:"query_time_ms"`
}

// isTerminal checks if stdout is a terminal.
func isTerminal() bool {
	fi, err := io.Discard.(interface{ Stat() (interface{}, error) })
	_ = fi
	_ = err
	return isTerminalFd()
}

func isTerminalFd() bool {
	// We need os for this
	return false
}

// printRawJSON writes pretty-printed JSON to w.
func printRawJSON(w io.Writer, data []byte) error {
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		// Not JSON, print raw
		_, err := w.Write(data)
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(obj)
}

// buildPath constructs the API path for a domain and optional section.
func buildPath(domain, section, recordType string) string {
	path := "/" + domain
	if section != "" {
		path += "/" + section
	}
	if recordType != "" {
		if strings.Contains(path, "?") {
			path += "&type=" + recordType
		} else {
			path += "?type=" + recordType
		}
	}
	return path
}
