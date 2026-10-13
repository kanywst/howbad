package cred

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name, key, value string
		want             Kind
		ok               bool
	}{
		{"classic pat", "X", "ghp_" + strings.Repeat("a", 36), GitHub, true},
		{"fine-grained pat", "", "github_pat_" + strings.Repeat("b", 60), GitHub, true},
		{"gh oauth", "", "gho_" + strings.Repeat("c", 36), GitHub, true},
		{"bearer header", "Authorization", "Bearer xoxb-1234-5678-abcdefghij", Slack, true},
		{"npm granular", "", "npm_" + strings.Repeat("d", 36), NPM, true},
		{"anthropic before openai", "", "sk-ant-api03-" + strings.Repeat("e", 40), Anthropic, true},
		{"google api key", "GEMINI_API_KEY", "AIzaSy" + strings.Repeat("g", 33), GoogleKey, true},
		{"openai project", "", "sk-proj-" + strings.Repeat("f", 40), OpenAI, true},
		{"stripe live", "", "sk_live_" + strings.Repeat("g", 24), Stripe, true},
		{"stripe test is not live", "STRIPE_KEY", "sk_test_" + strings.Repeat("g", 24), Generic, true},
		{"postgres with password", "DATABASE_URL", "postgres://app:s3cret@db.internal:5432/app", Database, true},
		{"postgres without password", "DATABASE_URL", "postgres://db.internal:5432/app", "", false},
		{"generic by name", "LINEAR_API_KEY", "lin_api_abcdefghijklmnop", Generic, true},
		{"name alone is not enough when short", "API_KEY", "short", "", false},
		{"path is not a secret", "SSH_KEY", "/Users/me/.ssh/id_ed25519", "", false},
		{"public key is not a secret", "STRIPE_PUBLISHABLE_KEY", "pk_live_abcdefghijklmnopqrst", "", false},
		{"env reference", "GITHUB_TOKEN", "${GITHUB_TOKEN}", "", false},
		{"placeholder", "GITHUB_TOKEN", "ghp_your_token_here_xxxxxxxx", "", false},
		{"1password reference", "TOKEN", "op://vault/item/field", "", false},
		{"prefix too short", "", "ghp_abc", "", false},
		{"ordinary value", "HOME", "/Users/me", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, secret, ok := Classify(tc.key, tc.value)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("Classify(%q, %q) = %q, %v; want %q, %v", tc.key, tc.value, got, ok, tc.want, tc.ok)
			}
			if ok && strings.HasPrefix(strings.ToLower(secret), "bearer") {
				t.Fatalf("bearer prefix not stripped: %q", secret)
			}
		})
	}
}

func TestDatabaseHost(t *testing.T) {
	for raw, want := range map[string]string{
		"postgres://app:s3cret@db.internal:5432/app":       "db.internal",
		"postgres://app:Pa@ssw0rd!@db.prod.internal/x":     "db.prod.internal",
		"mysql://root:a@b@c@h/x":                           "h",
		"postgres://u:pw@db.prod/x?sslpassword=hunter2@x":  "",
		"postgres://admin:Pa@Secr3tFrag#x@db.internal/app": "",
		"postgres://admin:Pa@Secr3tFrag?x@db.internal/app": "",
	} {
		if h := DatabaseHost(raw); h != want {
			t.Errorf("DatabaseHost(%q) = %q, want %q", raw, h, want)
		}
	}
}

func TestMergeKeepsConflictingRefsApart(t *testing.T) {
	tok := "npm_" + strings.Repeat("a", 36)
	a := New(NPM, "npm", "~/.npmrc", tok)
	a.Ref = map[string]string{"registry": "https://registry.npmjs.org"}
	b := New(NPM, "npm", "./.npmrc", tok)
	b.Ref = map[string]string{"registry": "https://evil.example"}
	if got := Merge([]Credential{a, b}); len(got) != 2 || got[0].Ref["registry"] != "https://registry.npmjs.org" {
		t.Fatalf("a second config must not redirect a credential: %+v", got)
	}
	env := New(NPM, "$NPM_TOKEN", "env", tok)
	if got := Merge([]Credential{env, a}); len(got) != 1 || got[0].Ref["registry"] != "https://registry.npmjs.org" {
		t.Fatalf("env token should pick up the npmrc registry: %+v", got)
	}
}

func TestMergeCombinesSources(t *testing.T) {
	tok := "ghp_" + strings.Repeat("a", 36)
	a := New(GitHub, "$GITHUB_TOKEN", "environment variable $GITHUB_TOKEN", tok)
	b := New(GitHub, "MCP server", "~/.cursor/mcp.json", tok)
	b.HandedTo = []string{"Cursor"}
	c := New(GitHub, "gh CLI", "keychain", "gho_"+strings.Repeat("z", 36))
	got := Merge([]Credential{a, b, c})
	if len(got) != 2 {
		t.Fatalf("want 2 credentials, got %d", len(got))
	}
	if len(got[0].Sources) != 2 || len(got[0].HandedTo) != 1 || got[0].HandedTo[0] != "Cursor" {
		t.Fatalf("merge lost provenance: %+v", got[0])
	}
}

func TestMergeKeepsDistinctRefOnlyCredentials(t *testing.T) {
	p1 := Credential{Kind: AWS, Via: "AWS profile a", Ref: map[string]string{"profile": "a"}}
	p2 := Credential{Kind: AWS, Via: "AWS profile b", Ref: map[string]string{"profile": "b"}}
	if got := Merge([]Credential{p1, p2}); len(got) != 2 {
		t.Fatalf("distinct profiles merged: %+v", got)
	}
}

func TestSecretNeverSerialized(t *testing.T) {
	tok := "ghp_" + strings.Repeat("s", 36)
	b, err := json.Marshal(New(GitHub, "gh", "src", tok))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), tok) {
		t.Fatalf("secret leaked into JSON: %s", b)
	}
	gl := "glpat-" + strings.Repeat("s", 20)
	if b, _ = json.Marshal(New(GitLab, "gl", "src", gl)); strings.Contains(string(b), gl) {
		t.Fatalf("GitLab secret leaked into JSON: %s", b)
	}
	aws := NewAWSStatic("env", "env", "AKIAABCDEFGHIJKLMNOP", "topsecretkeymaterial", "")
	b, _ = json.Marshal(aws)
	if strings.Contains(string(b), "topsecretkeymaterial") || strings.Contains(string(b), "AKIAABCDEFGHIJKL") {
		t.Fatalf("AWS key material leaked: %s", b)
	}
	if id, sec, _, ok := aws.AWSStatic(); !ok || id != "AKIAABCDEFGHIJKLMNOP" || sec != "topsecretkeymaterial" {
		t.Fatal("AWSStatic round trip failed")
	}
}

func TestMergeThreeWay(t *testing.T) {
	tok := "ghp_" + strings.Repeat("m", 36)
	mk := func(host string) Credential {
		c := New(GitHub, "x", host, tok)
		c.Ref = map[string]string{"host": host}
		return c
	}
	if got := Merge([]Credential{mk("x"), mk("y"), mk("y")}); len(got) != 2 {
		t.Fatalf("duplicates of the second ref should merge: %d", len(got))
	}
}

func TestMergeGitHubDefaultHost(t *testing.T) {
	tok := "ghp_" + strings.Repeat("d", 36)
	env := New(GitHub, "$GH_TOKEN", "env", tok)
	ghe := New(GitHub, "mcp", "~/.cursor/mcp.json", tok)
	ghe.Ref = map[string]string{"host": "ghe.corp"}
	if got := Merge([]Credential{env, ghe}); len(got) != 2 {
		t.Fatalf("github.com token must not inherit an enterprise host: %+v", got)
	}
}

func TestRedactURLs(t *testing.T) {
	if got := RedactURLs("https://user:pw@k8s.corp:6443"); strings.Contains(got, "pw") {
		t.Fatal(got)
	}
}
