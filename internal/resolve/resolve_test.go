package resolve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/aws/smithy-go"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

func server(t *testing.T, h http.HandlerFunc) Options {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return Options{HTTP: s.Client(), GitHubAPI: s.URL, NPMRegistry: s.URL, SlackAPI: s.URL, GitLabAPI: s.URL}
}

func requireBearer(t *testing.T, r *http.Request, tok string) bool {
	t.Helper()
	return r.Header.Get("Authorization") == "Bearer "+tok
}

func TestGitHubClassicToken(t *testing.T) {
	tok := "gho_" + strings.Repeat("a", 36)
	var o Options
	o = server(t, func(w http.ResponseWriter, r *http.Request) {
		if !requireBearer(t, r, tok) {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/user":
			w.Header().Set("X-OAuth-Scopes", "gist, read:org, repo, workflow")
			fmt.Fprint(w, `{"login":"me"}`)
		case r.URL.Path == "/user/repos" && r.URL.Query().Get("page") == "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/user/repos?page=2>; rel="next"`, o.GitHubAPI))
			fmt.Fprint(w, `[{"full_name":"me/big","stargazers_count":900,"permissions":{"admin":true,"push":true,"pull":true}},
				{"full_name":"me/archived","archived":true,"permissions":{"push":true}},
				{"full_name":"org/readonly","private":true,"permissions":{"pull":true}}]`)
		case r.URL.Path == "/user/repos":
			fmt.Fprint(w, `[{"full_name":"org/app","private":true,"stargazers_count":5,"permissions":{"push":true,"pull":true}}]`)
		default:
			w.WriteHeader(404)
		}
	})
	f := One(context.Background(), cred.New(cred.GitHub, "gh CLI", "keychain", tok), o)
	if f.Status != finding.OK || f.Identity != "me on github.com" {
		t.Fatalf("status %s identity %q detail %q", f.Status, f.Identity, f.Detail)
	}
	if f.Severity() != finding.Critical {
		t.Fatalf("severity %s", f.Severity())
	}
	push := f.Reach[0]
	if !strings.Contains(push.What, "push code to 2 GitHub repos and rewrite their CI workflows") || push.Inferred {
		t.Fatalf("push capability: %+v", push)
	}
	if push.Examples[0] != "me/big (900★)" {
		t.Fatalf("examples should be sorted by stars: %v", push.Examples)
	}
	if !hasWhat(f, "change settings on 1 repos") || !hasWhat(f, "secret gists") {
		t.Fatalf("missing admin or gist reach: %+v", f.Reach)
	}
}

func TestGitHubPublicRepoScopeCannotPushPrivate(t *testing.T) {
	tok := "ghp_" + strings.Repeat("b", 36)
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.Header().Set("X-OAuth-Scopes", "public_repo")
			fmt.Fprint(w, `{"login":"me"}`)
		case "/user/repos":
			fmt.Fprint(w, `[{"full_name":"me/pub","permissions":{"push":true}},{"full_name":"me/priv","private":true,"permissions":{"push":true}}]`)
		}
	})
	f := One(context.Background(), cred.New(cred.GitHub, "x", "y", tok), o)
	if !hasWhat(f, "push code to 1 GitHub repos") || hasWhat(f, "CI workflows") {
		t.Fatalf("public_repo scope should reach only the public repo and not workflows: %+v", f.Reach)
	}
}

func TestGitHubFineGrainedIsUpperBound(t *testing.T) {
	tok := "github_pat_" + strings.Repeat("c", 60)
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			fmt.Fprint(w, `{"login":"me"}`)
		case "/user/repos":
			fmt.Fprint(w, `[{"full_name":"me/one","private":true,"permissions":{"push":true}}]`)
		}
	})
	f := One(context.Background(), cred.New(cred.GitHub, "x", "y", tok), o)
	if !f.Reach[0].Inferred || !strings.Contains(f.Reach[0].What, "up to 1") {
		t.Fatalf("fine-grained token should be reported as an upper bound: %+v", f.Reach[0])
	}
}

func TestGitHubAppUserTokenWithEmptyScopes(t *testing.T) {
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.Header().Set("X-OAuth-Scopes", "")
			fmt.Fprint(w, `{"login":"me"}`)
		case "/user/repos":
			fmt.Fprint(w, `[{"full_name":"me/one","private":true,"permissions":{"push":true}}]`)
		}
	})
	f := One(context.Background(), cred.New(cred.GitHub, "x", "y", "ghu_"+strings.Repeat("u", 36)), o)
	if f.Severity() != finding.Critical || !f.Reach[0].Inferred {
		t.Fatalf("ghu_ token with an empty scope header must not be read as scopeless: %+v", f.Reach)
	}
}

func TestGitHubInstallationToken(t *testing.T) {
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.WriteHeader(403)
		case "/installation/repositories":
			fmt.Fprint(w, `{"total_count":7,"repositories":[{"full_name":"acme/app","stargazers_count":4}]}`)
		}
	})
	f := One(context.Background(), cred.New(cred.GitHub, "x", "y", "ghs_"+strings.Repeat("s", 36)), o)
	if f.Status != finding.OK || !hasWhat(f, "up to 7 GitHub repos") {
		t.Fatalf("%+v", f)
	}
}

func TestGitHubEnterpriseWithoutHostIsNotSent(t *testing.T) {
	o := server(t, func(_ http.ResponseWriter, r *http.Request) { t.Errorf("enterprise token sent to %s", r.URL) })
	c := cred.New(cred.GitHub, "$GH_ENTERPRISE_TOKEN", "env", "ghp_"+strings.Repeat("x", 36))
	c.Ref = map[string]string{"host": "unknown-enterprise"}
	if f := One(context.Background(), c, o); f.Status != finding.Unverified {
		t.Fatalf("%+v", f)
	}
}

func TestGitHubPaginationStaysOnHost(t *testing.T) {
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.Header().Set("X-OAuth-Scopes", "repo")
			fmt.Fprint(w, `{"login":"me"}`)
		case "/user/repos":
			w.Header().Set("Link", `<https://evil.example/steal?page=2>; rel="next"`)
			fmt.Fprint(w, `[{"full_name":"me/a","permissions":{"push":true}}]`)
		}
	})
	f := One(context.Background(), cred.New(cred.GitHub, "x", "y", "ghp_"+strings.Repeat("p", 36)), o)
	if f.Status != finding.OK || !hasWhat(f, "push code to 1+ GitHub repos") {
		t.Fatalf("cross-host next link should stop pagination and mark truncation: %+v", f.Reach)
	}
}

func TestGitHubRevoked(t *testing.T) {
	o := server(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) })
	f := One(context.Background(), cred.New(cred.GitHub, "x", "y", "ghp_"+strings.Repeat("d", 36)), o)
	if f.Status != finding.Invalid || f.Severity() != finding.None {
		t.Fatalf("revoked token: %+v", f)
	}
}

func TestNPMPublisher(t *testing.T) {
	tok := "npm_" + strings.Repeat("e", 36)
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/whoami":
			if !requireBearer(t, r, tok) {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"username":"me"}`)
		case "/-/v1/search":
			if r.URL.Query().Get("text") != "maintainer:me" {
				t.Errorf("search text %q", r.URL.Query().Get("text"))
			}
			if r.Header.Get("Authorization") != "" {
				t.Error("token sent to the public search endpoint")
			}
			fmt.Fprint(w, `{"objects":[{"package":{"name":"tiny"},"downloads":{"weekly":12}},
				{"package":{"name":"left-pad-ng"},"downloads":{"weekly":1500000}},
				{"package":{"name":"@me/scoped"},"downloads":{"weekly":3000}}]}`)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	f := One(context.Background(), cred.New(cred.NPM, "npm", "~/.npmrc", tok), o)
	if f.Status != finding.OK || f.Severity() != finding.Critical {
		t.Fatalf("%+v", f)
	}
	c := f.Reach[0]
	if !strings.Contains(c.What, "3 npm packages (1.5M downloads/week) unless npm demands 2FA") || c.Examples[0] != "left-pad-ng (1.5M/week)" || !c.Inferred {
		t.Fatalf("npm reach: %+v", c)
	}
}

func TestNPMBasicAuth(t *testing.T) {
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/whoami":
			if r.Header.Get("Authorization") != "Basic dXNlcjpwYXNz" {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"username":"user"}`)
		case "/-/v1/search":
			fmt.Fprint(w, `{"objects":[]}`)
		}
	})
	c := cred.New(cred.NPM, "npm", "~/.npmrc", "dXNlcjpwYXNz")
	c.Ref = map[string]string{"registry": "https://registry.npmjs.org", "scheme": "basic"}
	if f := One(context.Background(), c, o); f.Status != finding.OK || f.Severity() != finding.Medium {
		t.Fatalf("%+v", f)
	}
}

func TestNPMPrivateRegistryNotCalled(t *testing.T) {
	o := server(t, func(_ http.ResponseWriter, r *http.Request) { t.Errorf("unexpected call %s", r.URL) })
	c := cred.New(cred.NPM, "npm", "~/.npmrc", "tok-for-private-registry")
	c.Ref = map[string]string{"registry": "https://npm.pkg.github.com"}
	if f := One(context.Background(), c, o); f.Status != finding.Unverified {
		t.Fatalf("%+v", f)
	}
}

func TestSlack(t *testing.T) {
	tok := "xoxp-1-2-" + strings.Repeat("f", 24)
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth.test" || !requireBearer(t, r, tok) {
			fmt.Fprint(w, `{"ok":false,"error":"invalid_auth"}`)
			return
		}
		w.Header().Set("X-OAuth-Scopes", "channels:history,im:history,chat:write,users:read")
		fmt.Fprint(w, `{"ok":true,"team":"Acme","user":"me"}`)
	})
	f := One(context.Background(), cred.New(cred.Slack, "x", "y", tok), o)
	if f.Status != finding.OK || !hasWhat(f, "public channels, DMs") || !hasWhat(f, "post messages as me") {
		t.Fatalf("%+v", f)
	}
	f = One(context.Background(), cred.New(cred.Slack, "x", "y", "xoxb-wrong-"+strings.Repeat("x", 20)), o)
	if f.Status != finding.Invalid {
		t.Fatalf("invalid token: %+v", f)
	}
}

func TestOfflineMakesNoCalls(t *testing.T) {
	o := server(t, func(_ http.ResponseWriter, r *http.Request) { t.Errorf("network call in offline mode: %s", r.URL) })
	o.Offline = true
	sso := cred.Credential{Kind: cred.AWS, Via: "AWS profile p", Ref: map[string]string{"profile": "p", "role": "AWSReservedSSO_AdministratorAccess_0123abcd"}}
	for _, c := range []cred.Credential{
		cred.New(cred.GitHub, "x", "y", "ghp_"+strings.Repeat("g", 36)),
		cred.New(cred.NPM, "x", "y", "npm_"+strings.Repeat("g", 36)),
		sso,
	} {
		f := One(context.Background(), c, o)
		if f.Status != finding.Skipped {
			t.Fatalf("%s: %s", c.Kind, f.Status)
		}
		if c.Kind == cred.AWS && (f.Severity() != finding.Critical || !f.Reach[0].Inferred) {
			t.Fatalf("offline SSO admin role should be an inferred critical: %+v", f.Reach)
		}
	}
}

func TestNoExecSkips(t *testing.T) {
	o := Options{NoExec: true}
	o.defaults()
	k := cred.Credential{Kind: cred.Kube, Ref: map[string]string{"context": "c", "exec": "aws"}}
	if f := One(context.Background(), k, o); f.Status != finding.Skipped {
		t.Fatalf("kube exec plugin not skipped: %+v", f)
	}
	a := cred.Credential{Kind: cred.AWS, Ref: map[string]string{"profile": "p", "auth": "credential_process"}}
	if f := One(context.Background(), a, o); f.Status != finding.Skipped {
		t.Fatalf("credential_process not skipped: %+v", f)
	}
}

func TestUnverifiedKinds(t *testing.T) {
	f := One(context.Background(), cred.New(cred.Stripe, "x", "y", "sk_live_"+strings.Repeat("h", 24)), Options{})
	if f.Status != finding.Unverified || f.Severity() != finding.Critical {
		t.Fatalf("%+v", f)
	}
	f = One(context.Background(), cred.New(cred.Database, "x", "y", "postgres://u:p4ssword@db.prod:5432/x"), Options{})
	if !strings.Contains(f.Reach[0].What, "db.prod") || strings.Contains(f.Reach[0].What, "p4ssword") {
		t.Fatalf("database reach: %+v", f.Reach)
	}
}

func TestAWSCredError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		auth string
		want finding.Status
	}{
		{"timeout", fmt.Errorf("op: %w", context.DeadlineExceeded), "sso", finding.Unreachable},
		{"dns", &net.DNSError{Err: "no such host", Name: "sts.amazonaws.com"}, "static", finding.Unreachable},
		{"sso never logged in", fmt.Errorf("get credentials: failed to refresh cached credentials, failed to read cached SSO token file, open x.json: %w", &os.PathError{Op: "open", Path: "x.json", Err: syscall.ENOENT}), "sso", finding.Expired},
		{"sso expired", errors.New("failed to refresh cached credentials, the SSO session has expired or is invalid"), "sso", finding.Expired},
		{"credential_process failure is not sso", errors.New("failed to refresh cached credentials, process provider error: exit status 1"), "credential_process", finding.Error},
		{"api invalid", &smithy.GenericAPIError{Code: "InvalidClientTokenId"}, "static", finding.Invalid},
		{"api expired", &smithy.GenericAPIError{Code: "ExpiredToken"}, "static", finding.Expired},
	}
	for _, tc := range cases {
		if got, _ := awsCredError(tc.err, tc.auth); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}

func TestParseARN(t *testing.T) {
	cases := map[string][2]string{
		"arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_abc/me@corp": {"role", "AWSReservedSSO_Admin_abc"},
		"arn:aws:iam::111122223333:user/ops/alice":                                {"user", "alice"},
		"arn:aws:iam::111122223333:root":                                          {"root", ""},
	}
	for arn, want := range cases {
		k, n := parseARN(arn)
		if k != want[0] || n != want[1] {
			t.Errorf("parseARN(%q) = %q, %q", arn, k, n)
		}
	}
}

func TestClassifyPolicies(t *testing.T) {
	if c := classifyPolicies([]string{"ReadOnlyAccess", "AdministratorAccess"}, false); len(c) != 1 || c[0].Severity != finding.Critical {
		t.Fatalf("admin: %+v", c)
	}
	c := classifyPolicies([]string{"AmazonS3FullAccess", "AmazonEC2FullAccess", "custom-thing"}, false)
	if len(c) != 1 || c[0].Severity != finding.High || c[0].What != "fully control S3, EC2" {
		t.Fatalf("full access: %+v", c)
	}
	if c := classifyPolicies([]string{"inline"}, true); c[0].Severity != finding.Critical {
		t.Fatalf("inline star: %+v", c)
	}
	if c := classifyPolicies([]string{"custom"}, false); len(c) != 0 {
		t.Fatalf("custom policy should not be guessed: %+v", c)
	}
}

func TestGrantsStar(t *testing.T) {
	cases := map[string]bool{
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`:                                                     true,
		`{"Statement":{"Effect":"Allow","Action":["s3:*","*"],"Resource":["*"]}}`:                                            true,
		`%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22*%22%2C%22Resource%22%3A%22*%22%7D%5D%7D`: true,
		`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`:                                                      false,
		`{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`:                                                  false,
	}
	for doc, want := range cases {
		if got := grantsStar(doc); got != want {
			t.Errorf("grantsStar(%s) = %v", doc, got)
		}
	}
}

func TestInferFromRole(t *testing.T) {
	c, ok := inferFromRole("AWSReservedSSO_AdministratorAccess_0123456789abcdef")
	if !ok || c.Severity != finding.Critical || !strings.Contains(c.What, "AdministratorAccess)") {
		t.Fatalf("%+v", c)
	}
	if c, _ := inferFromRole("ReadOnly"); c.Severity != finding.High {
		t.Fatalf("%+v", c)
	}
	if _, ok := inferFromRole(""); ok {
		t.Fatal("empty role inferred")
	}
}

func hasWhat(f finding.Finding, sub string) bool {
	for _, c := range f.Reach {
		if strings.Contains(c.What, sub) {
			return true
		}
	}
	return false
}

func TestNPMLookalikeRegistryNotCalled(t *testing.T) {
	o := server(t, func(_ http.ResponseWriter, r *http.Request) { t.Errorf("unexpected call %s", r.URL) })
	for _, reg := range []string{"https://registry.npmjs.org.mirror.corp", "https://nexus.corp/repository/registry.npmjs.org"} {
		c := cred.New(cred.NPM, "npm", "~/.npmrc", "npm_"+strings.Repeat("l", 36))
		c.Ref = map[string]string{"registry": reg}
		if f := One(context.Background(), c, o); f.Status != finding.Unverified {
			t.Fatalf("%s: %+v", reg, f)
		}
	}
	c := cred.New(cred.NPM, "$NPM_TOKEN", "env", strings.Join([]string{"aaaaaaaa", "bbbb", "cccc", "dddd", "eeeeeeeeeeee"}, "-"))
	if f := One(context.Background(), c, o); f.Status != finding.Unverified {
		t.Fatalf("unprefixed token with no registry must not go to npmjs: %+v", f)
	}
}

func TestGitHubRepoListFailureIsPartial(t *testing.T) {
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.Header().Set("X-OAuth-Scopes", "repo")
			fmt.Fprint(w, `{"login":"me"}`)
		default:
			w.WriteHeader(502)
		}
	})
	f := One(context.Background(), cred.New(cred.GitHub, "x", "y", "ghp_"+strings.Repeat("f", 36)), o)
	if f.Status != finding.Partial || hasWhat(f, "public data only") || !hasWhat(f, "every repo me can write to") {
		t.Fatalf("a failed repo listing must keep an upper bound: %+v", f)
	}
}

func TestNoExecSkipsSourceProfileChain(t *testing.T) {
	o := Options{NoExec: true}
	o.defaults()
	c := cred.Credential{Kind: cred.AWS, Ref: map[string]string{"profile": "prod", "auth": "assume-role", "exec": "credential_process"}}
	if f := One(context.Background(), c, o); f.Status != finding.Skipped {
		t.Fatalf("%+v", f)
	}
}

func TestKubeNamespaceRBAC(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews") {
			w.WriteHeader(404)
			return
		}
		// client-go may encode as JSON, protobuf or CBOR; the strings survive all three.
		body, _ := io.ReadAll(r.Body)
		allowed := bytes.Contains(body, []byte("team")) && bytes.Contains(body, []byte("secrets"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","status":{"allowed":%v}}`, allowed)
	}))
	t.Cleanup(s.Close)
	kc := filepath.Join(t.TempDir(), "config")
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: %q}}]
users: [{name: u, user: {token: abc}}]
contexts: [{name: dev, context: {cluster: c, user: u, namespace: team}}]
current-context: dev
`, s.URL)
	if err := os.WriteFile(kc, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := cred.Credential{Kind: cred.Kube, Ref: map[string]string{"context": "dev", "kubeconfig": kc, "server": s.URL, "namespace": "team"}}
	o := Options{}
	o.defaults()
	f := One(context.Background(), c, o)
	if f.Status != finding.OK || !hasWhat(f, "read Secrets in namespace team") || f.Severity() != finding.Critical {
		t.Fatalf("namespace-scoped access missed: %+v", f)
	}
}

func TestNoExecUsesSDKParser(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config")
	body := "[profile a]\nrole_arn = arn:aws:iam::1:role/x\nSOURCE_PROFILE = b\n[profile b]\nCredential_Process: /usr/bin/false\n[profile clean]\naws_access_key_id = AKIA0000000000000000\naws_secret_access_key = x\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfg)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	if !sdkRunsProcess(context.Background(), "a") {
		t.Fatal("SDK-parsed chain with odd casing and ':' must count as running a process")
	}
	if sdkRunsProcess(context.Background(), "clean") {
		t.Fatal("static profile flagged as running a process")
	}
	if !sdkRunsProcess(context.Background(), "missing") {
		t.Fatal("unloadable profile must err on the side of skipping")
	}
}

func TestRepoLocalHostIsNotDialed(t *testing.T) {
	o := server(t, func(_ http.ResponseWriter, r *http.Request) { t.Errorf("dialed %s", r.URL) })
	c := cred.New(cred.GitHub, "x", "./.mcp.json", "ghp_"+strings.Repeat("r", 36))
	c.Ref = map[string]string{"host": "127.0.0.1:9"}
	c.RepoLocal = true
	if f := One(context.Background(), c, o); f.Status != finding.Unverified {
		t.Fatalf("%+v", f)
	}
}

func TestNoExecKeepsAGuess(t *testing.T) {
	o := Options{NoExec: true}
	o.defaults()
	a := cred.Credential{Kind: cred.AWS, Ref: map[string]string{"profile": "p", "auth": "assume-role", "exec": "credential_process", "role": "AdminRole"}}
	if f := One(context.Background(), a, o); f.Severity() != finding.Critical {
		t.Fatalf("--no-exec dropped the AWS role guess: %+v", f)
	}
	k := cred.Credential{Kind: cred.Kube, Ref: map[string]string{"context": "c", "exec": "aws"}}
	if f := One(context.Background(), k, o); len(f.Reach) == 0 {
		t.Fatalf("--no-exec kube skip has no reach: %+v", f)
	}
}

func gitlabServer(t *testing.T, tok, self string) Options {
	t.Helper()
	return server(t, func(w http.ResponseWriter, r *http.Request) {
		if !requireBearer(t, r, tok) || r.Header.Get("PRIVATE-TOKEN") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/personal_access_tokens/self":
			fmt.Fprint(w, self)
		case "/user":
			fmt.Fprint(w, `{"username":"me","is_admin":false}`)
		default:
			t.Errorf("unexpected GitLab call %s", r.URL)
		}
	})
}

func TestGitLabScopes(t *testing.T) {
	tok := "glpat-" + strings.Repeat("g", 20)
	o := gitlabServer(t, tok, `{"scopes":["api","self_rotate"],"user_id":7,"active":true}`)
	f := One(context.Background(), cred.New(cred.GitLab, "x", "y", tok), o)
	if f.Status != finding.OK || f.Identity != "me on gitlab.com" || f.Severity() != finding.Critical || !hasWhat(f, "CI/CD") || !hasWhat(f, "rotate") {
		t.Fatalf("%+v", f)
	}

	o = gitlabServer(t, tok, `{"scopes":["read_repository"],"user_id":7,"active":true}`)
	f = One(context.Background(), cred.New(cred.GitLab, "x", "y", tok), o)
	if f.Severity() != finding.High || !hasWhat(f, "read every private") {
		t.Fatalf("read-only token: %+v", f)
	}

	wrong := cred.New(cred.GitLab, "x", "y", "glpat-wrong-"+strings.Repeat("w", 20))
	// A 401 may mean another instance issued it: never report it dead.
	if f = One(context.Background(), wrong, o); f.Status != finding.Unverified || f.Severity() != finding.Critical || !f.Reach[0].Inferred {
		t.Fatalf("rejected token: %+v", f)
	}
}

func TestGitLabFineGrainedIsUpperBound(t *testing.T) {
	tok := "glpat-" + strings.Repeat("f", 20)
	o := gitlabServer(t, tok, `{"scopes":[],"granular_scopes":[{"access":"all_memberships"}],"user_id":7,"active":true}`)
	f := One(context.Background(), cred.New(cred.GitLab, "x", "y", tok), o)
	if f.Severity() != finding.Critical || !f.Reach[0].Inferred {
		t.Fatalf("fine-grained token must report the owner's reach as inferred: %+v", f)
	}
}

func TestGitLabSelfUnavailableIsUpperBound(t *testing.T) {
	tok := "glpat-" + strings.Repeat("p", 20)
	o := server(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	f := One(context.Background(), cred.New(cred.GitLab, "x", "y", tok), o)
	if f.Status != finding.Partial || f.Severity() != finding.Critical || !f.Reach[0].Inferred {
		t.Fatalf("%+v", f)
	}
}

func TestGitLabRepoLocalHostIsNotDialed(t *testing.T) {
	o := server(t, func(_ http.ResponseWriter, r *http.Request) { t.Errorf("dialed %s", r.URL) })
	c := cred.New(cred.GitLab, "x", "./.mcp.json", "glpat-"+strings.Repeat("r", 20))
	c.Ref = map[string]string{"host": "127.0.0.1:9"}
	c.RepoLocal = true
	if f := One(context.Background(), c, o); f.Status != finding.Unverified {
		t.Fatalf("%+v", f)
	}
}

func TestGitLabTokenDoesNotFollowRedirect(t *testing.T) {
	tok := "glpat-" + strings.Repeat("d", 20)
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization")+r.Header.Get("PRIVATE-TOKEN"), tok) {
			t.Errorf("token followed a redirect to another host")
		}
	}))
	t.Cleanup(other.Close)
	target := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+r.URL.Path, http.StatusFound)
	})
	One(context.Background(), cred.New(cred.GitLab, "x", "y", tok), o)
}

func TestGitLabAdminAndRegistry(t *testing.T) {
	tok := "glpat-" + strings.Repeat("a", 20)
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			fmt.Fprint(w, `{"username":"root","is_admin":true}`)
			return
		}
		fmt.Fprint(w, `{"scopes":["api"],"user_id":1,"active":true}`)
	})
	if f := One(context.Background(), cred.New(cred.GitLab, "x", "y", tok), o); !hasWhat(f, "administer the GitLab instance") {
		t.Fatalf("admin api token: %+v", f)
	}
	o = gitlabServer(t, tok, `{"scopes":["read_registry"],"user_id":7,"active":true}`)
	if f := One(context.Background(), cred.New(cred.GitLab, "x", "y", tok), o); !hasWhat(f, "pull private container images") {
		t.Fatalf("read_registry: %+v", f)
	}
	o = gitlabServer(t, tok, `{"scopes":[],"granular_scopes":{"x":1},"user_id":7,"active":true}`)
	if f := One(context.Background(), cred.New(cred.GitLab, "x", "y", tok), o); f.Status != finding.OK || f.Severity() != finding.Critical {
		t.Fatalf("object granular_scopes / empty scopes: %+v", f)
	}
}

func TestGitLabUnknownHostIsNotSent(t *testing.T) {
	o := server(t, func(_ http.ResponseWriter, r *http.Request) { t.Errorf("dialed %s", r.URL) })
	c := cred.New(cred.GitLab, "x", "y", "glpat-"+strings.Repeat("u", 20))
	c.Ref = map[string]string{"host": "unknown-self-managed"}
	if f := One(context.Background(), c, o); f.Status != finding.Unverified {
		t.Fatalf("%+v", f)
	}
}

func TestGitLabSelfRejectedButUserAccepted(t *testing.T) {
	tok := "glpat-" + strings.Repeat("n", 20)
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" && requireBearer(t, r, tok) {
			fmt.Fprint(w, `{"username":"me"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	f := One(context.Background(), cred.New(cred.GitLab, "x", "y", tok), o)
	if f.Status != finding.Partial || f.Severity() != finding.Critical || !f.Reach[0].Inferred {
		t.Fatalf("live token reported dead: %+v", f)
	}
	o = gitlabServer(t, tok, `{"scopes":["api"],"user_id":7}`)
	if f := One(context.Background(), cred.New(cred.GitLab, "x", "y", tok), o); f.Status != finding.OK {
		t.Fatalf("missing active field read as inactive: %+v", f)
	}
}
