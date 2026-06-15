// Package output provides formatters for ns CLI results.
package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/yokedotlol/ns-lol/cli/cmd"
)

// ANSI color codes.
const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	White  = "\033[37m"
)

func c(noColor bool, color, text string) string {
	if noColor {
		return text
	}
	return color + text + Reset
}

func gradeColor(grade string) string {
	switch {
	case grade == "A+" || grade == "A":
		return Green
	case grade == "B":
		return Yellow
	default:
		return Red
	}
}

func statusIcon(status string, noColor bool) string {
	switch status {
	case "pass":
		return c(noColor, Green, "✓")
	case "warn":
		return c(noColor, Yellow, "⚠")
	case "fail":
		return c(noColor, Red, "✗")
	case "info":
		return c(noColor, Dim, "ℹ")
	default:
		return " "
	}
}

// ─── DNS Lookup ─────────────────────────────────────────────────────

// PrettyLookup renders a full DNS lookup result.
func PrettyLookup(w io.Writer, resp *cmd.LookupResponse, noColor bool) {
	// Header
	fmt.Fprintf(w, "\n  %s%s\n",
		c(noColor, Bold, resp.Domain),
		c(noColor, Dim, fmt.Sprintf("    %d records · %d types · %s",
			resp.Summary.TotalRecords,
			resp.Summary.RecordTypes,
			resp.Summary.DNSSEC)))
	fmt.Fprintf(w, "  %s\n\n", c(noColor, Dim, strings.Repeat("─", 60)))

	// Record type display order
	typeOrder := []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "HTTPS", "DNSKEY", "DS"}

	// First show types in preferred order
	shown := map[string]bool{}
	for _, t := range typeOrder {
		section, ok := resp.Records[t]
		if !ok || len(section.Records) == 0 {
			continue
		}
		printRecordSection(w, t, section, noColor)
		shown[t] = true
	}

	// Then show any remaining types not in the preferred order
	for t, section := range resp.Records {
		if shown[t] || len(section.Records) == 0 {
			continue
		}
		printRecordSection(w, t, section, noColor)
	}

	// Footer
	fmt.Fprintf(w, "  %s\n\n",
		c(noColor, Dim, fmt.Sprintf("→ Full report: https://yoke.lol/%s", resp.Domain)))
}

func printRecordSection(w io.Writer, typeName string, section cmd.RecordTypeSection, noColor bool) {
	fmt.Fprintf(w, "  %s%s\n",
		c(noColor, Cyan+Bold, fmt.Sprintf("%-6s", typeName)),
		c(noColor, Dim, fmt.Sprintf("  %dms", section.QueryTimeMs)))

	for i, rec := range section.Records {
		prefix := "├─"
		if i == len(section.Records)-1 {
			prefix = "└─"
		}

		data := rec.Data
		ttl := rec.TTLHuman
		if ttl == "" {
			ttl = fmt.Sprintf("%ds", rec.TTL)
		}

		// Truncate very long records
		if len(data) > 72 {
			data = data[:69] + "..."
		}

		fmt.Fprintf(w, "  %s %-56s %s\n",
			c(noColor, Dim, prefix),
			data,
			c(noColor, Dim, ttl))
	}
	fmt.Fprintln(w)
}

// ─── Signal-based checks (health, email, security) ──────────────────

// PrettySignals renders a signal-based check result.
func PrettySignals(w io.Writer, resp *cmd.SignalResponse, section string, noColor bool) {
	var grade *cmd.SignalGrade
	title := ""
	switch section {
	case "health":
		grade = resp.Health
		title = "DNS Health"
	case "email":
		grade = resp.Email
		title = "Email Security"
	case "security":
		grade = resp.Security
		title = "DNSSEC & Security"
	}

	// Header with grade
	fmt.Fprintln(w)
	if grade != nil {
		gc := gradeColor(grade.Grade)
		fmt.Fprintf(w, "  %s%-50s%s  %s\n",
			c(noColor, Bold, ""),
			resp.Domain,
			"",
			c(noColor, Bold+gc, grade.Grade))
		fmt.Fprintf(w, "  %s    %s\n",
			c(noColor, Cyan, title),
			c(noColor, Dim, fmt.Sprintf("%d checked · %d pass · %d warn · %d fail",
				grade.SignalsChecked, grade.Pass, grade.Warn, grade.Fail)))
	} else {
		fmt.Fprintf(w, "  %s  %s\n",
			c(noColor, Bold, resp.Domain),
			c(noColor, Cyan, title))
	}
	fmt.Fprintf(w, "  %s\n\n", c(noColor, Dim, strings.Repeat("─", 60)))

	// Group signals by category
	type catGroup struct {
		name    string
		signals []cmd.Signal
	}
	var groups []catGroup
	groupMap := map[string]int{}

	for _, sig := range resp.Signals {
		idx, ok := groupMap[sig.Category]
		if !ok {
			idx = len(groups)
			groupMap[sig.Category] = idx
			groups = append(groups, catGroup{name: sig.Category})
		}
		groups[idx].signals = append(groups[idx].signals, sig)
	}

	for _, g := range groups {
		fmt.Fprintf(w, "  %s\n", c(noColor, Cyan, g.name))
		for i, sig := range g.signals {
			prefix := "├─"
			if i == len(g.signals)-1 {
				prefix = "└─"
			}

			icon := statusIcon(sig.Status, noColor)
			label := fmt.Sprintf("%-24s", sig.Label)
			detail := sig.Detail
			if len(detail) > 50 {
				detail = detail[:47] + "..."
			}

			fmt.Fprintf(w, "  %s %s %s  %s\n",
				c(noColor, Dim, prefix),
				icon,
				label,
				c(noColor, Dim, detail))

			if sig.Fix != "" {
				fixPrefix := "   "
				if i < len(g.signals)-1 {
					fixPrefix = "│  "
				}
				fix := sig.Fix
				if len(fix) > 70 {
					fix = fix[:67] + "..."
				}
				fmt.Fprintf(w, "  %s   %s\n",
					c(noColor, Dim, fixPrefix),
					c(noColor, Yellow, "→ "+fix))
			}
		}
		fmt.Fprintln(w)
	}

	// Footer
	fmt.Fprintf(w, "  %s\n\n",
		c(noColor, Dim, fmt.Sprintf("→ Full report: https://yoke.lol/%s", resp.Domain)))
}

// ─── Propagation ────────────────────────────────────────────────────

// PrettyPropagation renders a propagation check result.
func PrettyPropagation(w io.Writer, resp *cmd.PropagationResponse, noColor bool) {
	pct := resp.Propagation.Percentage

	// Header
	fmt.Fprintln(w)
	pctColor := Green
	if pct < 100 {
		pctColor = Yellow
	}
	if pct < 50 {
		pctColor = Red
	}

	fmt.Fprintf(w, "  %s  %s  %s\n",
		c(noColor, Bold, resp.Domain),
		c(noColor, Cyan, resp.Type+" Propagation"),
		c(noColor, Bold+pctColor, fmt.Sprintf("%d%%", pct)))

	fmt.Fprintf(w, "  %s\n",
		c(noColor, Dim, fmt.Sprintf("  %d/%d resolvers responded · %d distinct answers",
			resp.Propagation.ResolversResponded,
			resp.Propagation.ResolversQueried,
			resp.Propagation.DistinctAnswers)))

	if resp.Propagation.TTL != nil {
		fmt.Fprintf(w, "  %s\n",
			c(noColor, Dim, fmt.Sprintf("  TTL range: %s – %s",
				resp.Propagation.TTL.MinHuman,
				resp.Propagation.TTL.MaxHuman)))
	}

	fmt.Fprintf(w, "  %s\n\n", c(noColor, Dim, strings.Repeat("─", 60)))

	// Progress bar
	barWidth := 40
	filled := (pct * barWidth) / 100
	if pct > 0 && filled == 0 {
		filled = 1
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Fprintf(w, "  %s\n\n", c(noColor, pctColor, bar))

	// Distinct answers
	if len(resp.Answers) > 0 {
		fmt.Fprintf(w, "  %s\n", c(noColor, Cyan, "Distinct Answers"))
		for i, ans := range resp.Answers {
			prefix := "├─"
			if i == len(resp.Answers)-1 {
				prefix = "└─"
			}

			values := strings.Join(ans.Value, ", ")
			resolvers := strings.Join(ans.Resolvers, ", ")
			if len(resolvers) > 40 {
				resolvers = resolvers[:37] + "..."
			}

			majority := ""
			if ans.IsMajority {
				majority = c(noColor, Green, " ★")
			}

			fmt.Fprintf(w, "  %s %-28s %s%s\n",
				c(noColor, Dim, prefix),
				values,
				c(noColor, Dim, fmt.Sprintf("(%d) %s", ans.Count, resolvers)),
				majority)
		}
		fmt.Fprintln(w)
	}

	// Footer
	fmt.Fprintf(w, "  %s\n\n",
		c(noColor, Dim, fmt.Sprintf("→ Full report: https://yoke.lol/%s", resp.Domain)))
}

// ─── Compare ────────────────────────────────────────────────────────

// PrettyCompare renders a side-by-side DNS comparison.
func PrettyCompare(w io.Writer, a, b *cmd.LookupResponse, noColor bool) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", c(noColor, Cyan, "DNS Compare"))
	fmt.Fprintf(w, "  %s\n\n", c(noColor, Dim, strings.Repeat("─", 60)))

	// Header
	fmt.Fprintf(w, "  %-22s  %-24s  %-24s\n",
		"",
		c(noColor, Bold, a.Domain),
		c(noColor, Bold, b.Domain))
	fmt.Fprintf(w, "  %s\n", c(noColor, Dim, strings.Repeat("─", 74)))

	// Summary comparison
	compareLine(w, "Total Records",
		fmt.Sprintf("%d", a.Summary.TotalRecords),
		fmt.Sprintf("%d", b.Summary.TotalRecords), noColor)
	compareLine(w, "Record Types",
		fmt.Sprintf("%d", a.Summary.RecordTypes),
		fmt.Sprintf("%d", b.Summary.RecordTypes), noColor)
	compareLine(w, "DNSSEC", a.Summary.DNSSEC, b.Summary.DNSSEC, noColor)
	compareLine(w, "Avg Query Time",
		fmt.Sprintf("%dms", a.Summary.AvgQueryMs),
		fmt.Sprintf("%dms", b.Summary.AvgQueryMs), noColor)

	// Compare record types
	allTypes := map[string]bool{}
	for t := range a.Records {
		allTypes[t] = true
	}
	for t := range b.Records {
		allTypes[t] = true
	}

	typeOrder := []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "HTTPS"}
	shown := map[string]bool{}

	for _, t := range typeOrder {
		if !allTypes[t] {
			continue
		}
		aCount := len(a.Records[t].Records)
		bCount := len(b.Records[t].Records)
		compareLine(w, t+" records",
			fmt.Sprintf("%d", aCount),
			fmt.Sprintf("%d", bCount), noColor)
		shown[t] = true
	}
	for t := range allTypes {
		if shown[t] {
			continue
		}
		aCount := len(a.Records[t].Records)
		bCount := len(b.Records[t].Records)
		compareLine(w, t+" records",
			fmt.Sprintf("%d", aCount),
			fmt.Sprintf("%d", bCount), noColor)
	}

	fmt.Fprintln(w)
}

func compareLine(w io.Writer, label, valA, valB string, noColor bool) {
	diff := ""
	if valA != valB {
		diff = c(noColor, Yellow, "  ≠")
	}
	fmt.Fprintf(w, "  %-22s  %-24s  %-24s%s\n",
		c(noColor, Dim, label),
		valA, valB, diff)
}
