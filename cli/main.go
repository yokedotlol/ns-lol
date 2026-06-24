// ns — fast, API-first DNS lookup. Same engine as ns.lol.
//
// Usage:
//
//	ns <domain>                       Full DNS lookup (all record types)
//	ns <domain> -t <type>             Query specific record type
//	ns <domain> propagation           Propagation check across global resolvers
//	ns <domain> health                DNS health check
//	ns <domain> email                 Email security audit
//	ns <domain> spf                   Deep SPF analysis (lookup budget, include tree)
//	ns <domain> security              DNSSEC & security check
//	ns compare <a> <b>                Side-by-side DNS comparison
//	ns version                        Print version info
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yokedotlol/ns-lol/cli/cmd"
)

// Injected at build time via ldflags.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	args := os.Args[1:]

	// Stdin pipe: read domains from stdin if no args and stdin is a pipe
	if len(args) == 0 {
		if isPipe() {
			domains := readStdin()
			if len(domains) > 0 {
				cfg := &config{}
				opts := buildOpts(cfg)
				code := 0
				for _, d := range domains {
					c := cmd.RunLookup(os.Stdout, d, opts)
					code = maxCode(code, c)
				}
				os.Exit(code)
			}
		}
		usage()
		os.Exit(2)
	}

	// Check for subcommands first
	switch args[0] {
	case "compare":
		cfg, err := parseArgs(args[1:])
		if err != nil {
			fatal(err)
		}
		if len(cfg.targets) < 2 {
			fmt.Fprintf(os.Stderr, "error: compare requires exactly 2 domains\n")
			os.Exit(2)
		}
		opts := buildOpts(cfg)
		code := cmd.RunCompare(os.Stdout, cfg.targets[0], cfg.targets[1], opts)
		os.Exit(code)

	case "version":
		fmt.Printf("ns %s (%s)\nhttps://ns.lol\n", version, commit)
		return

	case "help", "--help", "-h":
		usage()
		return

	default:
		// Fall through to lookup
	}

	cfg, err := parseArgs(args)
	if err != nil {
		fatal(err)
	}

	if len(cfg.targets) == 0 {
		fmt.Fprintf(os.Stderr, "error: no domain specified\n")
		usage()
		os.Exit(2)
	}

	opts := buildOpts(cfg)
	domain := cfg.targets[0]

	// Check for subcommand after domain
	if cfg.subcommand != "" {
		var code int
		switch cfg.subcommand {
		case "propagation":
			code = cmd.RunPropagation(os.Stdout, domain, opts)
		case "health":
			code = cmd.RunHealth(os.Stdout, domain, opts)
		case "email":
			code = cmd.RunEmail(os.Stdout, domain, opts)
		case "spf":
			code = cmd.RunSPF(os.Stdout, domain, opts)
		case "security":
			code = cmd.RunSecurity(os.Stdout, domain, opts)
		default:
			fmt.Fprintf(os.Stderr, "error: unknown subcommand %q\n", cfg.subcommand)
			os.Exit(2)
		}
		os.Exit(code)
	}

	// Default: full DNS lookup
	code := cmd.RunLookup(os.Stdout, domain, opts)
	os.Exit(code)
}

// ─── Arg parsing ────────────────────────────────────────────────────

type config struct {
	jsonOut    bool
	quiet      bool
	noColor    bool
	recordType string
	timeout    string
	subcommand string
	targets    []string
}

func parseArgs(args []string) (*config, error) {
	cfg := &config{
		timeout: "30s",
	}

	// Respect NO_COLOR env var (https://no-color.org/)
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		cfg.noColor = true
	}

	i := 0
	for i < len(args) {
		arg := args[i]

		// Handle --flag=value syntax
		eqIdx := -1
		if strings.HasPrefix(arg, "--") {
			eqIdx = strings.Index(arg, "=")
		}
		var eqVal string
		if eqIdx > 0 {
			eqVal = arg[eqIdx+1:]
			arg = arg[:eqIdx]
		}

		switch arg {
		case "--json", "-j":
			cfg.jsonOut = true
		case "--quiet", "-q":
			cfg.quiet = true
		case "--no-color":
			cfg.noColor = true

		case "--type", "-t":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			cfg.recordType = strings.ToUpper(v)

		case "--timeout":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			cfg.timeout = v

		case "-p":
			// shortcut for propagation
			cfg.subcommand = "propagation"

		default:
			if strings.HasPrefix(arg, "-") {
				return nil, fmt.Errorf("unknown flag: %s", arg)
			}
			// Check if it's a known subcommand (after the domain)
			if len(cfg.targets) > 0 && cfg.subcommand == "" {
				switch arg {
				case "propagation", "health", "email", "security", "spf":
					cfg.subcommand = arg
				default:
					cfg.targets = append(cfg.targets, arg)
				}
			} else {
				cfg.targets = append(cfg.targets, arg)
			}
		}

		i++
	}

	return cfg, nil
}

func getVal(args []string, i *int, eqIdx int, eqVal, flag string) (string, error) {
	if eqIdx > 0 {
		return eqVal, nil
	}
	*i++
	if *i >= len(args) {
		return "", fmt.Errorf("%s requires a value", flag)
	}
	return args[*i], nil
}

func buildOpts(cfg *config) cmd.Options {
	timeout, err := time.ParseDuration(cfg.timeout)
	if err != nil {
		timeout = 30 * time.Second
	}

	return cmd.Options{
		JSON:       cfg.jsonOut,
		Quiet:      cfg.quiet,
		NoColor:    cfg.noColor,
		RecordType: cfg.recordType,
		Timeout:    timeout,
		Version:    version,
	}
}

func isPipe() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeNamedPipe != 0
}

func readStdin() []string {
	var domains []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, line)
	}
	return domains
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(2)
}

func maxCode(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func usage() {
	fmt.Fprintf(os.Stderr, `ns %s — fast, API-first DNS lookup

Usage:
  ns <domain>                         Full DNS lookup (all record types)
  ns <domain> -t <type>               Query specific record type
  ns <domain> propagation             Propagation check (global resolvers)
  ns <domain> -p                      Shortcut for propagation
  ns <domain> health                  DNS health audit
  ns <domain> email                   Email security audit (SPF/DKIM/DMARC)
  ns <domain> spf                     Deep SPF analysis (lookup budget, include tree)
  ns <domain> security                DNSSEC & security check
  ns compare <a> <b>                  Side-by-side DNS comparison
  ns version                          Version info

Output:
  -j, --json                          JSON output (default when piped)
  -q, --quiet                         Exit code only
      --no-color                      Disable ANSI colors (also: NO_COLOR env)

Options:
  -t, --type <TYPE>                   Record type (A, AAAA, MX, NS, TXT, etc.)
      --timeout <dur>                 Request timeout (default 30s)

Pipe support:
  echo "example.com" | ns             Read domains from stdin

Exit codes:
  0    Lookup succeeded
  1    Lookup succeeded, issues found
  2    Usage error or request failed

https://ns.lol/cli
`, version)
}
