package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

func awsFinding(profile, arn string) finding.Finding {
	f := finding.Finding{
		Credential: cred.Credential{Kind: cred.AWS, Via: "AWS profile " + profile, Sources: []string{"~/.aws/config"}},
		Identity:   arn,
		Status:     finding.OK,
	}
	f.Add(finding.Critical, "do anything")
	return f
}

func TestDedupeMergesSamePrincipal(t *testing.T) {
	got := Dedupe([]finding.Finding{
		awsFinding("a", "arn:aws:sts::1:assumed-role/Admin/x"),
		awsFinding("b", "arn:aws:sts::1:assumed-role/Admin/x"),
		awsFinding("c", "arn:aws:sts::2:assumed-role/Admin/x"),
	})
	if len(got) != 2 || got[0].Credential.Via != "AWS profile a, b" {
		t.Fatalf("%+v", got)
	}
}

func TestHighestCountsOfflineGuessesButNotExpired(t *testing.T) {
	skipped := finding.Finding{Status: finding.Skipped}
	skipped.Add(finding.Critical, "guess")
	expired := finding.Finding{Status: finding.Expired}
	expired.Add(finding.Critical, "later")
	if Highest([]finding.Finding{expired}) != finding.None {
		t.Fatal("expired credentials are not reachable now")
	}
	if Highest([]finding.Finding{skipped}) != finding.Critical {
		t.Fatal("--offline --fail-on must see offline guesses")
	}
}

func TestTextGroupsProvenance(t *testing.T) {
	slack := finding.Finding{Credential: cred.New(cred.Slack, "MCP server \"slack\" (Cursor)", "~/.cursor/mcp.json", "xoxb-secret-value-123456"), Status: finding.OK, Identity: "me in Acme"}
	slack.Add(finding.High, "read history")
	slack.Add(finding.High, "post messages")
	var b bytes.Buffer
	Text(&b, Report{Found: 3, Findings: []finding.Finding{slack}}, false)
	out := b.String()
	if strings.Count(out, "↳") != 1 {
		t.Errorf("provenance should print once per credential run:\n%s", out)
	}
	if strings.Contains(out, "xoxb-secret") {
		t.Errorf("secret leaked:\n%s", out)
	}
	if !strings.Contains(out, "3 credentials · 1 verified") {
		t.Errorf("footer should count credentials found, not merged findings:\n%s", out)
	}
}

func TestTextEmpty(t *testing.T) {
	var b bytes.Buffer
	Text(&b, Report{}, true)
	if strings.Contains(b.String(), "-v shows") {
		t.Errorf("verbose output should not suggest -v:\n%s", b.String())
	}
}

func TestTextStripsControlCharacters(t *testing.T) {
	f := finding.Finding{Credential: cred.Credential{Kind: cred.NPM, Via: "npm\x1b]52;c;evil\x07", Sources: []string{"./.npmrc\x1b[2J"}}, Status: finding.Unverified}
	f.Add(finding.High, "publish to \x1b[2J\x1b[Hregistry")
	var b bytes.Buffer
	Text(&b, Report{Findings: []finding.Finding{f}}, true)
	if strings.ContainsRune(b.String(), 0x1b) || strings.ContainsRune(b.String(), 0x07) {
		t.Fatalf("control characters reached the terminal: %q", b.String())
	}
}

func TestJSONEscapesC1AndBidi(t *testing.T) {
	f := finding.Finding{Status: finding.Unverified}
	f.Add(finding.High, "host\u009b2J\u202eevil")
	var b bytes.Buffer
	if err := JSON(&b, Report{Findings: []finding.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(b.String(), 0x9b) || strings.ContainsRune(b.String(), 0x202e) {
		t.Fatalf("raw control rune in JSON: %q", b.String())
	}
	if !strings.Contains(b.String(), `\u009b`) {
		t.Fatalf("expected escaped C1: %s", b.String())
	}
}
