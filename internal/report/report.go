package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/discover"
	"github.com/kanywst/howbad/internal/finding"
)

type Report struct {
	Version  string
	Found    int
	Agents   []discover.Agent
	Findings []finding.Finding
}

func counts(f finding.Finding) bool {
	switch f.Status {
	case finding.OK, finding.Unverified:
		return true
	case finding.Skipped, finding.Partial:
		return len(f.Reach) > 0
	}
	return false
}

// Unreachable counts credentials whose reach was not fully checked. A guess
// is not an upper bound, so --fail-on must not pass on one.
func Unreachable(fs []finding.Finding) int {
	n := 0
	for _, f := range fs {
		switch f.Status {
		case finding.Unreachable, finding.Error, finding.Skipped, finding.Partial:
			n++
		}
	}
	return n
}

func Highest(fs []finding.Finding) finding.Severity {
	max := finding.None
	for _, f := range fs {
		if counts(f) && f.Severity() > max {
			max = f.Severity()
		}
	}
	return max
}

func Dedupe(fs []finding.Finding) []finding.Finding {
	var out []finding.Finding
	idx := map[string]int{}
	for _, f := range fs {
		if f.Status != finding.OK || f.Identity == "" || (f.Credential.Kind != cred.AWS && f.Credential.Kind != cred.Kube) {
			out = append(out, f)
			continue
		}
		k := string(f.Credential.Kind) + "|" + f.Identity
		if i, ok := idx[k]; ok {
			out[i].Credential.Via += ", " + strings.TrimPrefix(strings.TrimPrefix(f.Credential.Via, "AWS profile "), "kube context ")
			for _, s := range f.Credential.Sources {
				if !contains(out[i].Credential.Sources, s) {
					out[i].Credential.Sources = append(out[i].Credential.Sources, s)
				}
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, f)
	}
	return out
}

type row struct {
	cap finding.Capability
	f   finding.Finding
	idx int
}

type styles struct {
	sev   map[finding.Severity]lipgloss.Style
	dim   lipgloss.Style
	bold  lipgloss.Style
	title lipgloss.Style
}

func newStyles(w io.Writer) styles {
	r := lipgloss.NewRenderer(w)
	return styles{
		sev: map[finding.Severity]lipgloss.Style{
			finding.Critical: r.NewStyle().Bold(true).Foreground(lipgloss.Color("9")),
			finding.High:     r.NewStyle().Bold(true).Foreground(lipgloss.Color("208")),
			finding.Medium:   r.NewStyle().Foreground(lipgloss.Color("11")),
			finding.Low:      r.NewStyle().Foreground(lipgloss.Color("12")),
			finding.Info:     r.NewStyle().Faint(true),
		},
		dim:   r.NewStyle().Faint(true),
		bold:  r.NewStyle().Bold(true),
		title: r.NewStyle().Bold(true),
	}
}

func Text(w io.Writer, r Report, verbose bool) {
	st := newStyles(w)
	floor := finding.Medium
	if verbose {
		floor = finding.Info
	}
	var rows []row
	var later, unchecked []finding.Finding
	hidden := 0
	for i, f := range r.Findings {
		switch {
		case counts(f):
			for _, c := range f.Reach {
				if c.Severity >= floor {
					rows = append(rows, row{c, f, i})
				} else {
					hidden++
				}
			}
		case f.Status == finding.Expired && len(f.Reach) > 0:
			later = append(later, f)
		default:
			unchecked = append(unchecked, f)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].cap.Severity > rows[j].cap.Severity })

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+st.title.Render("howbad")+st.dim.Render(" · if a coding agent on this machine got hijacked right now, it could:"))
	fmt.Fprintln(w)
	if len(rows) == 0 {
		msg := "  nothing above low severity found."
		if len(unchecked) > 0 {
			msg = "  nothing above low severity confirmed."
		}
		if !verbose {
			msg += " -v shows everything."
		}
		fmt.Fprintln(w, msg)
	}
	for n, rw := range rows {
		label := strings.ToUpper(rw.cap.Severity.String())
		what := clean(rw.cap.What)
		var tags []string
		if rw.cap.Inferred {
			tags = append(tags, "inferred")
		}
		if rw.f.Status == finding.Unverified {
			tags = append(tags, "not verified")
		}
		if rw.f.Status == finding.Skipped {
			tags = append(tags, "not checked")
		}
		if rw.f.Status == finding.Partial {
			tags = append(tags, "check incomplete")
		}
		if len(tags) > 0 {
			what += st.dim.Render(" (" + strings.Join(tags, ", ") + ")")
		}
		fmt.Fprintf(w, "  %s  %s\n", st.sev[rw.cap.Severity].Render(fmt.Sprintf("%-8s", label)), what)
		if len(rw.cap.Examples) > 0 {
			fmt.Fprintf(w, "            %s\n", st.dim.Render(clean("e.g. "+strings.Join(rw.cap.Examples, ", "))))
		}
		if n == len(rows)-1 || rows[n+1].idx != rw.idx {
			fmt.Fprintf(w, "            %s\n", st.dim.Render(clean("↳ "+provenance(rw.f))))
		}
	}

	if len(later) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.bold.Render("  one login away:"))
		for _, f := range later {
			for _, c := range f.Reach {
				fmt.Fprintf(w, "    %s: %s\n", clean(f.Credential.Via), clean(c.What))
			}
		}
	}
	if len(unchecked) > 0 {
		fmt.Fprintln(w)
		if verbose {
			fmt.Fprintln(w, st.bold.Render("  not checked:"))
			for _, f := range unchecked {
				fmt.Fprintf(w, "    %s %s: %s\n", st.dim.Render("["+string(f.Status)+"]"), clean(f.Credential.Via), clean(f.Detail))
			}
		} else {
			fmt.Fprintf(w, "  %s\n", st.dim.Render(fmt.Sprintf("%s could not be checked; -v lists them", plural(len(unchecked), "credential", "credentials"))))
		}
	}
	if hidden > 0 && !verbose {
		fmt.Fprintf(w, "  %s\n", st.dim.Render(fmt.Sprintf("%d lower-severity item(s) hidden; -v shows them", hidden)))
	}

	fmt.Fprintln(w)
	if len(r.Agents) > 0 {
		var names []string
		for _, a := range r.Agents {
			n := a.Name
			if a.Posture != "" {
				n += " " + st.sev[finding.High].Render("("+a.Posture+")")
			}
			names = append(names, n)
		}
		fmt.Fprintf(w, "  agents running as you: %s\n", strings.Join(names, ", "))
	}
	handed, verified := 0, 0
	for _, f := range r.Findings {
		if len(f.Credential.HandedTo) > 0 {
			handed++
		}
		if f.Status == finding.OK {
			verified++
		}
	}
	if handed > 0 {
		fmt.Fprintf(w, "  pasted straight into agent configs: %s\n", plural(handed, "credential", "credentials"))
	}
	fmt.Fprintf(w, "  %s\n", st.dim.Render(fmt.Sprintf("%s · %d verified read-only with the issuer · nothing sent anywhere else",
		plural(max(r.Found, len(r.Findings)), "credential", "credentials"), verified)))
}

// Repo configs and provider responses must not drive the terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return '?'
		}
		return r
	}, s)
}

func provenance(f finding.Finding) string {
	parts := []string{f.Credential.Via}
	if f.Identity != "" {
		parts = append(parts, f.Identity)
	}
	parts = append(parts, strings.Join(f.Credential.Sources, ", "))
	if f.Credential.Fingerprint != "" {
		parts = append(parts, "#"+f.Credential.Fingerprint)
	}
	return strings.Join(parts, " · ")
}

type jsonDoc struct {
	Tool        string            `json:"tool"`
	Version     string            `json:"version"`
	GeneratedAt time.Time         `json:"generated_at"`
	Highest     finding.Severity  `json:"highest_severity"`
	Agents      []discover.Agent  `json:"agents"`
	Findings    []finding.Finding `json:"findings"`
}

func JSON(w io.Writer, r Report) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	agents := r.Agents
	if agents == nil {
		agents = []discover.Agent{}
	}
	findings := r.Findings
	if findings == nil {
		findings = []finding.Finding{}
	}
	if err := enc.Encode(jsonDoc{
		Tool: "howbad", Version: r.Version, GeneratedAt: time.Now().UTC(),
		Highest: Highest(r.Findings), Agents: agents, Findings: findings,
	}); err != nil {
		return err
	}
	// encoding/json leaves DEL, C1 and bidi controls raw; escape them so
	// --json on a terminal is as inert as the text report.
	var b strings.Builder
	for _, c := range buf.String() {
		if (c >= 0x7f && c < 0xa0) || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) {
			fmt.Fprintf(&b, "\\u%04x", c)
			continue
		}
		b.WriteRune(c)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
