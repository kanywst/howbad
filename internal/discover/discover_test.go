package discover

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/howbad/internal/cred"
)

var (
	ghpMCP   = "ghp_" + strings.Repeat("m", 36)
	ghoCLI   = "gho_" + strings.Repeat("k", 36)
	npmTok   = "npm_" + strings.Repeat("n", 36)
	slackTok = "xoxb-1111-2222-" + strings.Repeat("s", 24)
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fakeHome(t *testing.T) Env {
	t.Helper()
	home := t.TempDir()
	write(t, filepath.Join(home, ".npmrc"), "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken="+npmTok+"\n//npm.pkg.github.com/:_authToken=${GH_PKG}\n")
	write(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "github.com:\n    user: me\n    git_protocol: https\n")
	write(t, filepath.Join(home, ".aws", "config"), `[default]
region = us-east-1

[profile prod-admin]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = AdministratorAccess

[profile ci]
role_arn = arn:aws:iam::444455556666:role/Deployer
source_profile = default

[profile region-only]
region = eu-west-1

[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
`)
	write(t, filepath.Join(home, ".aws", "credentials"), "[default]\naws_access_key_id = AKIAEXAMPLEKEY000000\naws_secret_access_key = abc\n")
	write(t, filepath.Join(home, ".kube", "config"), `apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster: {server: "https://prod.k8s.example:6443"}
users:
- name: eks
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
contexts:
- name: prod
  context: {cluster: prod, user: eks}
current-context: prod
`)
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"github":{"command":"docker","env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"`+ghpMCP+`"}}},
"projects":{"/Users/me/work/app":{"mcpServers":{"db":{"command":"npx","args":["-y","pg-mcp","postgres://app:pw123456@db.prod:5432/app"]}}}}}`)
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":{"slack":{"url":"https://mcp.example/sse","headers":{"Authorization":"Bearer `+slackTok+`"}},
"same-gh":{"command":"x","env":{"GITHUB_TOKEN":"`+ghpMCP+`"}}}}`)
	write(t, filepath.Join(home, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\n[mcp_servers.aws]\ncommand = \"uvx\"\nenv = { AWS_ACCESS_KEY_ID = \"AKIAMCPKEY0000000000\", AWS_SECRET_ACCESS_KEY = \"mcpsecret\" }\n")

	return Env{
		Home: home,
		Cwd:  home,
		GOOS: "darwin",
		Vars: map[string]string{"GH_PKG": "ghp_" + strings.Repeat("p", 36), "PATH": "/usr/bin"},
		Exec: func(_ context.Context, name string, args ...string) (string, error) {
			if name == "gh" && strings.Join(args, " ") == "auth token --hostname github.com" {
				return ghoCLI + "\n", nil
			}
			return "", errors.New("unexpected helper")
		},
	}
}

func byVia(cs []cred.Credential, kind cred.Kind, via string) *cred.Credential {
	for i := range cs {
		if cs[i].Kind == kind && strings.Contains(cs[i].Via, via) {
			return &cs[i]
		}
	}
	return nil
}

func TestRunFindsEverything(t *testing.T) {
	env := fakeHome(t)
	res := Run(context.Background(), env)
	cs := res.Credentials

	gh := byVia(cs, cred.GitHub, "gh CLI")
	if gh == nil || gh.Secret() != ghoCLI || gh.Sources[0] != "OS keychain via `gh auth token`" {
		t.Fatalf("gh CLI token via keychain not found: %+v", gh)
	}

	mcp := byVia(cs, cred.GitHub, `"github"`)
	if mcp == nil {
		t.Fatal("GitHub token in ~/.claude.json not found")
	}
	if len(mcp.HandedTo) != 2 || len(mcp.Sources) != 2 {
		t.Fatalf("same token in Claude Code and Cursor should merge: handed=%v sources=%v", mcp.HandedTo, mcp.Sources)
	}

	if c := byVia(cs, cred.Database, "db (project /Users/me/work/app)"); c == nil {
		t.Fatal("database URL in project-scoped MCP args not found")
	}
	if c := byVia(cs, cred.Slack, `"slack"`); c == nil || c.Secret() != slackTok {
		t.Fatal("Slack bearer header not found or not normalized")
	}

	var npmPublic *cred.Credential
	for i := range cs {
		if cs[i].Kind == cred.NPM && cs[i].Ref["registry"] == "https://registry.npmjs.org" {
			npmPublic = &cs[i]
		}
	}
	if npmPublic == nil || npmPublic.Secret() != npmTok {
		t.Fatal("npmjs token not found")
	}
	var pkg *cred.Credential
	for i := range cs {
		if cs[i].Secret() == env.Vars["GH_PKG"] {
			pkg = &cs[i]
		}
	}
	if pkg == nil || pkg.Kind != cred.GitHub || pkg.Ref["host"] != "github.com" || len(pkg.Sources) != 2 {
		t.Fatalf("GitHub PAT in .npmrc (via ${VAR}) should be resolved as a GitHub token: %+v", pkg)
	}

	profiles := map[string]map[string]string{}
	for _, c := range cs {
		if c.Kind == cred.AWS && c.Ref["profile"] != "" {
			profiles[c.Ref["profile"]] = c.Ref
		}
	}
	if _, ok := profiles["region-only"]; ok {
		t.Fatal("region-only profile has nothing to authenticate with and should be skipped")
	}
	if p := profiles["prod-admin"]; p["auth"] != "sso" || p["role"] != "AdministratorAccess" || p["account"] != "111122223333" {
		t.Fatalf("sso profile parsed wrong: %v", p)
	}
	if p := profiles["ci"]; p["auth"] != "assume-role" || p["role"] != "Deployer" || p["account"] != "444455556666" {
		t.Fatalf("assume-role profile parsed wrong: %v", p)
	}
	if p := profiles["default"]; p["auth"] != "static" {
		t.Fatalf("default static profile parsed wrong: %v", p)
	}
	if c := byVia(cs, cred.AWS, `"aws" (Codex)`); c == nil || c.Ref["key_id_suffix"] != "0000" || len(c.HandedTo) != 1 {
		t.Fatal("static AWS keys in Codex MCP env not found")
	}

	if c := byVia(cs, cred.Kube, "prod"); c == nil || c.Ref["exec"] != "aws" || c.Ref["server"] != "https://prod.k8s.example:6443" {
		t.Fatalf("kube context not parsed: %+v", c)
	}

	postures := map[string]string{}
	for _, a := range res.Agents {
		postures[a.Name] = a.Posture
	}
	if postures["Claude Code"] != "bypassPermissions" {
		t.Fatalf("Claude Code posture: %q", postures["Claude Code"])
	}
	if postures["Codex"] != "danger-full-access, never asks" {
		t.Fatalf("Codex posture: %q", postures["Codex"])
	}
	if _, ok := postures["Cursor"]; !ok {
		t.Fatal("Cursor not detected")
	}
}

func TestNoExecSkipsHelpers(t *testing.T) {
	env := fakeHome(t)
	env.Exec = nil
	for _, c := range Run(context.Background(), env).Credentials {
		if c.Via == "gh CLI" {
			t.Fatal("gh token found without running gh")
		}
	}
}

func TestEmptyHome(t *testing.T) {
	res := Run(context.Background(), Env{Home: t.TempDir(), Vars: map[string]string{}})
	if len(res.Credentials) != 0 || len(res.Agents) != 0 {
		t.Fatalf("expected nothing, got %+v", res)
	}
}

func TestEnvVars(t *testing.T) {
	env := Env{Home: t.TempDir(), Vars: map[string]string{
		"GITHUB_TOKEN":          "ghp_" + strings.Repeat("e", 36),
		"NPM_TOKEN":             "0b5c6f7e-1234-5678-9abc-def012345678",
		"AWS_ACCESS_KEY_ID":     "AKIAENVKEY0000001234",
		"AWS_SECRET_ACCESS_KEY": "envsecret",
		"EDITOR":                "vim",
	}}
	cs := Run(context.Background(), env).Credentials
	kinds := map[cred.Kind]int{}
	for _, c := range cs {
		kinds[c.Kind]++
	}
	if kinds[cred.GitHub] != 1 || kinds[cred.NPM] != 1 || kinds[cred.AWS] != 1 || len(cs) != 3 {
		t.Fatalf("unexpected env credentials: %v", kinds)
	}
}

func TestMCPArgShapes(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	tokA := "ghp_" + strings.Repeat("a", 36)
	tokB := "ghp_" + strings.Repeat("b", 36)
	tokC := "ghp_" + strings.Repeat("c", 36)
	tokD := "ghp_" + strings.Repeat("d", 36)
	write(t, filepath.Join(home, ".claude.json"), `{"projects":{
		"/w/api":{"mcpServers":{"gh":{"args":["run","-e","GITHUB_PERSONAL_ACCESS_TOKEN=`+tokA+`","img"]}}},
		"/p/api":{"mcpServers":{"gh":{"args":["mcp-remote","https://x","--header","Authorization: Bearer `+tokB+`"]}}}}}`)
	write(t, filepath.Join(cwd, ".vscode", "mcp.json"), `{"servers":{"gh":{"command":"x","args":["--token",`+"\""+tokC+"\""+`]}},"inputs":[]}`)
	write(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.gh]\ncommand = \"x\"\n[mcp_servers.gh.env]\nGITHUB_TOKEN = \""+tokD+"\"\nGITHUB_HOST = \"https://ghe.corp.example/\"\n")
	cs := Run(context.Background(), Env{Home: home, Cwd: cwd, Vars: map[string]string{}}).Credentials
	got := map[string]*cred.Credential{}
	for i := range cs {
		got[cs[i].Secret()] = &cs[i]
	}
	for name, tok := range map[string]string{"docker -e": tokA, "--header": tokB, "--token value (VS Code servers)": tokC, "codex nested env": tokD} {
		if got[tok] == nil {
			t.Errorf("%s: token not found", name)
		}
	}
	if got[tokA] != nil && got[tokB] != nil && got[tokA].Via == got[tokB].Via {
		t.Errorf("same-named projects collapsed: %q", got[tokA].Via)
	}
	if c := got[tokD]; c != nil && c.Ref["host"] != "ghe.corp.example" {
		t.Errorf("GITHUB_HOST next to the token should pin it: %v", c.Ref)
	}
}

func TestEnterpriseEnvTokenNeedsHost(t *testing.T) {
	tok := "ghp_" + strings.Repeat("e", 36)
	cs := Run(context.Background(), Env{Home: t.TempDir(), Vars: map[string]string{"GH_ENTERPRISE_TOKEN": tok}}).Credentials
	if len(cs) != 1 || cs[0].Ref["host"] != "unknown-enterprise" {
		t.Fatalf("%+v", cs)
	}
	cs = Run(context.Background(), Env{Home: t.TempDir(), Vars: map[string]string{"GH_ENTERPRISE_TOKEN": tok, "GH_HOST": "ghe.corp"}}).Credentials
	if cs[0].Ref["host"] != "ghe.corp" {
		t.Fatalf("%+v", cs[0].Ref)
	}
}

func TestNPMLegacyAuth(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".npmrc"), "//registry.npmjs.org/:_auth=dXNlcjpwYXNz\n//npm.corp:4873/:username=bob\n//npm.corp:4873/:_password=cGFzcw==\n//npm.corp:4873/:always-auth=true\n")
	cs := Run(context.Background(), Env{Home: home, Vars: map[string]string{}}).Credentials
	if len(cs) != 2 {
		t.Fatalf("want 2 npm credentials, got %+v", cs)
	}
	for _, c := range cs {
		if c.Ref["scheme"] != "basic" {
			t.Errorf("basic scheme missing: %v", c.Ref)
		}
	}
	if cs[1].Secret() != "Ym9iOnBhc3M=" || cs[1].Ref["registry"] != "https://npm.corp:4873" {
		t.Errorf("_password not combined with username: %q %v", cs[1].Secret(), cs[1].Ref)
	}
}

func TestProjectSettingsDoNotSetPosture(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	write(t, filepath.Join(cwd, ".claude", "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	write(t, filepath.Join(cwd, ".claude", "settings.local.json"), `{"env":{"OPENAI_API_KEY":"sk-proj-`+strings.Repeat("o", 40)+`"}}`)
	res := Run(context.Background(), Env{Home: home, Cwd: cwd, Vars: map[string]string{}})
	for _, a := range res.Agents {
		if a.Posture != "" {
			t.Errorf("project settings should not set posture: %+v", a)
		}
	}
	if len(res.Credentials) != 1 || res.Credentials[0].Kind != cred.OpenAI {
		t.Errorf("settings.local.json env not scanned: %+v", res.Credentials)
	}
}

func TestGoogleApplicationCredentials(t *testing.T) {
	home := t.TempDir()
	key := filepath.Join(home, "sa.json")
	write(t, key, "{}")
	cs := Run(context.Background(), Env{Home: home, Vars: map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": key}}).Credentials
	if len(cs) != 1 || cs[0].Kind != cred.GCP || cs[0].Ref["keyfile"] != "true" {
		t.Fatalf("%+v", cs)
	}
}

func TestSourceProfileChainMarksExec(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".aws", "config"), `[profile base]
credential_process = /usr/bin/false
[profile prod]
role_arn = arn:aws:iam::1:role/Admin
source_profile = base
[profile dangling]
role_arn = arn:aws:iam::1:role/Admin
source_profile = missing
[profile plain]
role_arn = arn:aws:iam::1:role/Admin
source_profile = keys
[profile keys]
aws_access_key_id = AKIA0000000000000000
`)
	exec := map[string]string{}
	for _, c := range Run(context.Background(), Env{Home: home, Vars: map[string]string{}}).Credentials {
		exec[c.Ref["profile"]] = c.Ref["exec"]
	}
	for p, want := range map[string]string{"base": "credential_process", "prod": "credential_process", "dangling": "credential_process", "plain": "", "keys": ""} {
		if exec[p] != want {
			t.Errorf("profile %s: exec=%q want %q", p, exec[p], want)
		}
	}
}

func TestHostileRepoNPMRC(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	write(t, filepath.Join(cwd, ".npmrc"), "//registry.npmjs.org/:_authToken=${AWS_SECRET_ACCESS_KEY}\n//\x1b[2Jx/:_authToken=npm_"+strings.Repeat("z", 36)+"\n")
	cs := Run(context.Background(), Env{Home: home, Cwd: cwd, Vars: map[string]string{"AWS_SECRET_ACCESS_KEY": "topsecret"}}).Credentials
	if len(cs) != 0 {
		t.Fatalf("a repo .npmrc must not expand env vars or accept a malformed registry: %+v", cs)
	}
}

func TestDeviceFilesAreNotRead(t *testing.T) {
	cwd := t.TempDir()
	if err := os.Symlink("/dev/zero", filepath.Join(cwd, ".mcp.json")); err != nil {
		t.Skip(err)
	}
	res := Run(context.Background(), Env{Home: t.TempDir(), Cwd: cwd, Vars: map[string]string{}})
	if len(res.Credentials) != 0 {
		t.Fatal("unexpected credentials")
	}
}

func TestProjectUnderHomeDoesNotSetPosture(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "repo")
	write(t, filepath.Join(cwd, ".claude", "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	for _, a := range Run(context.Background(), Env{Home: home, Cwd: cwd, Vars: map[string]string{}}).Agents {
		if a.Posture != "" {
			t.Fatalf("project settings under home set posture: %+v", a)
		}
	}
}

func TestHeaderArgVariants(t *testing.T) {
	home := t.TempDir()
	a := "ghp_" + strings.Repeat("1", 36)
	b := "ghp_" + strings.Repeat("2", 36)
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":{
		"a":{"args":["mcp-remote","https://x","--header","Authorization:Bearer `+a+`"]},
		"b":{"args":["mcp-remote","https://x","--header=Authorization: Bearer `+b+`"]},
		"c":{"args":["--port=8080","--header","Content-Type: application/json"]}}}`)
	cs := Run(context.Background(), Env{Home: home, Vars: map[string]string{}}).Credentials
	if len(cs) != 2 {
		t.Fatalf("want exactly the two bearer tokens, got %d: %+v", len(cs), cs)
	}
}

func TestGHHostOnlyPinsEnterpriseTokens(t *testing.T) {
	tok := "ghp_" + strings.Repeat("h", 36)
	cs := Run(context.Background(), Env{Home: t.TempDir(), Vars: map[string]string{"GITHUB_TOKEN": tok, "GH_HOST": "ghe.corp"}}).Credentials
	if len(cs) != 1 || cs[0].Ref["host"] != "" {
		t.Fatalf("GITHUB_TOKEN belongs to github.com even with GH_HOST set: %+v", cs[0].Ref)
	}
	cs = Run(context.Background(), Env{Home: t.TempDir(), Vars: map[string]string{"GH_TOKEN": tok, "GH_HOST": "acme.ghe.com"}}).Credentials
	if cs[0].Ref["host"] != "acme.ghe.com" {
		t.Fatalf("*.ghe.com tenants use GH_TOKEN: %+v", cs[0].Ref)
	}
	if r := githubHostRef("X", "https://api.acme.ghe.com"); r["host"] != "acme.ghe.com" {
		t.Fatalf("api. prefix not stripped for ghe.com: %v", r)
	}
}

func TestParseINIMatchesSDK(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".aws", "config"), "[profile a] # comment\nrole_arn: arn:aws:iam::1:role/x\nSOURCE_PROFILE = b\n[profile b]\nCredential_Process = /usr/bin/false\n")
	for _, c := range Run(context.Background(), Env{Home: home, Vars: map[string]string{}}).Credentials {
		if c.Ref["profile"] == "a" && c.Ref["exec"] == "" {
			t.Fatalf("chain not detected: %+v", c.Ref)
		}
	}
}

func TestGitHubPackagesHost(t *testing.T) {
	for reg, want := range map[string]string{
		"npm.pkg.github.com":                  "github.com",
		"npm.pkg.acme.ghe.com":                "acme.ghe.com",
		"npm.ghe.corp.example":                "ghe.corp.example",
		"ghe.corp.example/_registry/npm":      "ghe.corp.example",
		"registry.example.com/repository/npm": "unknown-enterprise",
	} {
		if got := githubPackagesHost(reg); got != want {
			t.Errorf("%s: got %s want %s", reg, got, want)
		}
	}
	if !enterpriseName("GHES_PAT") || !enterpriseName("GHE_TOKEN") || enterpriseName("GITHUB_TOKEN") {
		t.Error("enterpriseName")
	}
}

func TestDeepProjectsDoNotHang(t *testing.T) {
	cwd := t.TempDir()
	var b strings.Builder
	for i := 0; i < 3000; i++ {
		b.WriteString(`{"projects":{"p":`)
	}
	b.WriteString("{}")
	for i := 0; i < 3000; i++ {
		b.WriteString("}}")
	}
	write(t, filepath.Join(cwd, ".mcp.json"), b.String())
	done := make(chan struct{})
	go func() {
		Run(context.Background(), Env{Home: t.TempDir(), Cwd: cwd, Vars: map[string]string{}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("nested projects in a repo config hang discovery")
	}
}

func TestRepoLocalMarking(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	tok := "ghp_" + strings.Repeat("l", 36)
	write(t, filepath.Join(cwd, ".mcp.json"), `{"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"`+tok+`","GITHUB_HOST":"user:pw@evil"}}}}`)
	cs := Run(context.Background(), Env{Home: home, Cwd: cwd, Vars: map[string]string{}}).Credentials
	if len(cs) != 1 || !cs[0].RepoLocal || cs[0].Ref["host"] != "" {
		t.Fatalf("repo-local token should be marked and a userinfo host rejected: %+v", cs)
	}
	cs = Run(context.Background(), Env{Home: home, Cwd: cwd, Vars: map[string]string{"GITHUB_TOKEN": tok}}).Credentials
	if len(cs) != 1 || cs[0].RepoLocal {
		t.Fatalf("a token also found outside the repo is not repo-local: %+v", cs)
	}
}

func TestNormalizeHostRejectsTricks(t *testing.T) {
	for _, h := range []string{"evil.com#.ghe.com", "evil.com?.ghe.com", `evil.com\.ghe.com`, "u:p@h", "h/x"} {
		if got := normalizeHost(h); got != "" {
			t.Errorf("normalizeHost(%q) = %q", h, got)
		}
	}
	if normalizeHost("https://ghe.corp/") != "ghe.corp" {
		t.Error("plain URL broken")
	}
}
