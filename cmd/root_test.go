package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/howbad/internal/discover"
	"github.com/kanywst/howbad/internal/resolve"
)

var (
	ghTok    = "ghp_" + strings.Repeat("t", 36)
	dbURL    = "postgres://app:hunter2hunter2@db.prod.internal:5432/app"
	stripeSK = "sk_live_" + strings.Repeat("q", 24)
	glTok    = "glpat-" + strings.Repeat("k", 20)
)

func setup(t *testing.T) (discover.Env, resolve.Options) {
	t.Helper()
	home := t.TempDir()
	cfg := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"mcpServers":{"gh":{"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":%q}},"db":{"args":[%q]}}}`, ghTok, dbURL)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.Header().Set("X-OAuth-Scopes", "repo")
			fmt.Fprint(w, `{"login":"me"}`)
		case "/personal_access_tokens/self":
			fmt.Fprint(w, `{"scopes":["api"],"user_id":9,"active":true}`)
		case "/user/repos":
			fmt.Fprint(w, `[{"full_name":"me/app","stargazers_count":3,"permissions":{"push":true}}]`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.Close)
	env := discover.Env{Home: home, Cwd: home, GOOS: "linux", Vars: map[string]string{"STRIPE_SECRET_KEY": stripeSK, "GITLAB_TOKEN": glTok}}
	return env, resolve.Options{HTTP: s.Client(), GitHubAPI: s.URL, GitLabAPI: s.URL}
}

func execute(t *testing.T, env discover.Env, o resolve.Options, args ...string) (string, error) {
	t.Helper()
	c := NewRootCmd(env, o)
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetArgs(args)
	err := c.Execute()
	return out.String(), err
}

func assertNoSecrets(t *testing.T, out string) {
	t.Helper()
	for _, s := range []string{ghTok, dbURL, "hunter2hunter2", stripeSK, glTok} {
		if strings.Contains(out, s) {
			t.Fatalf("secret %q leaked into output:\n%s", s, out)
		}
	}
}

func TestTextReport(t *testing.T) {
	env, o := setup(t)
	out, err := execute(t, env, o)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, out)
	for _, want := range []string{
		"CRITICAL  push code to 1 GitHub repos",
		"e.g. me/app (3★)",
		`MCP server "gh" (Cursor) · me on github.com · ~/.cursor/mcp.json`,
		"move money on a live Stripe account",
		"edit CI/CD pipelines and variables",
		"connect to database db.prod.internal",
		"agents running as you: Cursor",
		"pasted straight into agent configs: 2 credentials",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "CRITICAL") > strings.Index(out, "HIGH") {
		t.Errorf("critical rows should come first:\n%s", out)
	}
}

func TestJSONReport(t *testing.T) {
	env, o := setup(t)
	out, err := execute(t, env, o, "--json")
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, out)
	var doc struct {
		Highest  string `json:"highest_severity"`
		Findings []struct {
			Status   string `json:"status"`
			Severity string `json:"severity"`
			Cred     struct {
				Kind     string   `json:"kind"`
				HandedTo []string `json:"handed_to"`
			} `json:"credential"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc.Highest != "critical" || len(doc.Findings) != 4 {
		t.Fatalf("unexpected document: %+v", doc)
	}
}

func TestFailOn(t *testing.T) {
	env, o := setup(t)
	if _, err := execute(t, env, o, "--fail-on", "critical"); !errors.Is(err, errThreshold) {
		t.Fatalf("want threshold error, got %v", err)
	}
	if _, err := execute(t, env, o, "--fail-on", "bogus"); err == nil || errors.Is(err, errThreshold) {
		t.Fatalf("bad severity should be a usage error, got %v", err)
	}
	clean := discover.Env{Home: t.TempDir(), Vars: map[string]string{}}
	if _, err := execute(t, clean, o, "--fail-on", "low"); err != nil {
		t.Fatalf("clean machine should pass: %v", err)
	}
}

func TestOnlyAndOffline(t *testing.T) {
	env, _ := setup(t)
	o := resolve.Options{HTTP: &http.Client{Transport: failTransport{t}}}
	out, err := execute(t, env, o, "--offline", "--only", "github", "-v")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Stripe") || strings.Contains(out, "database") {
		t.Fatalf("--only github leaked other kinds:\n%s", out)
	}
	if !strings.Contains(out, "use a GitHub token as its owner (inferred, not checked)") {
		t.Fatalf("offline guess not reported:\n%s", out)
	}
}

type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("network call with --offline: %s", r.URL)
	return nil, errors.New("offline")
}

func TestOnlyRejectsUnknownKind(t *testing.T) {
	env, o := setup(t)
	if _, err := execute(t, env, o, "--only", "k8s"); err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("want unknown kind error, got %v", err)
	}
}

func TestOfflineFailOnSeesUncheckedTokens(t *testing.T) {
	env := discover.Env{Home: t.TempDir(), Vars: map[string]string{"GITHUB_TOKEN": ghTok}}
	for _, level := range []string{"high", "critical"} {
		if _, err := execute(t, env, resolve.Options{}, "--offline", "--fail-on", level); !errors.Is(err, errThreshold) {
			t.Fatalf("--offline --fail-on %s passed with an unchecked GitHub token: %v", level, err)
		}
	}
}

func TestFailOnUnreachable(t *testing.T) {
	env := discover.Env{Home: t.TempDir(), Vars: map[string]string{"GITHUB_TOKEN": ghTok}}
	o := resolve.Options{HTTP: &http.Client{Transport: downTransport{}}}
	out, err := execute(t, env, o, "--fail-on", "critical")
	if !errors.Is(err, errThreshold) || !strings.Contains(out, "could not be checked") {
		t.Fatalf("a network outage must not pass --fail-on: %v\n%s", err, out)
	}
}

type downTransport struct{}

func (downTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &net.OpError{Op: "dial", Err: errors.New("connection refused")}
}
