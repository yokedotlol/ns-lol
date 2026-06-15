// Package cmd provides command orchestration for the ns CLI.
package cmd

import (
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
