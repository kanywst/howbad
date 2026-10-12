// Command demo runs howbad against a fake home directory and fake providers.
// It exists to record assets/demo.gif without touching real credentials.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/kanywst/howbad/cmd"
	"github.com/kanywst/howbad/internal/discover"
	"github.com/kanywst/howbad/internal/resolve"
)

func main() {
	home, err := os.MkdirTemp("", "howbad-demo")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(home) }()

	files := map[string]string{
		".config/gh/hosts.yml":  "github.com:\n    oauth_token: gho_" + strings.Repeat("D", 36) + "\n",
		".npmrc":                "//registry.npmjs.org/:_authToken=npm_" + strings.Repeat("D", 36) + "\n",
		".claude/settings.json": `{"permissions":{"defaultMode":"bypassPermissions"}}`,
		".cursor/mcp.json": `{"mcpServers":{"slack":{"url":"https://mcp.example/sse",
			"headers":{"Authorization":"Bearer xoxp-1-2-` + strings.Repeat("d", 24) + `"}}}}`,
		".codex/config.toml": "",
		".aws/config": "[profile prod]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = AdministratorAccess\n" +
			"[sso-session corp]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = us-east-1\n",
	}
	for p, body := range files {
		full := filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			panic(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			panic(err)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(fake))
	defer srv.Close()

	env := discover.Env{Home: home, Cwd: home, GOOS: "darwin", Vars: map[string]string{
		"OPENAI_API_KEY":              "sk-proj-" + strings.Repeat("D", 40),
		"AWS_CONFIG_FILE":             filepath.Join(home, ".aws", "config"),
		"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(home, ".aws", "credentials"),
	}}
	for _, k := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		if err := os.Setenv(k, env.Vars[k]); err != nil {
			panic(err)
		}
	}
	if err := os.Setenv("HOME", home); err != nil {
		panic(err)
	}

	opts := resolve.Options{HTTP: srv.Client(), GitHubAPI: srv.URL, NPMRegistry: srv.URL, SlackAPI: srv.URL}
	root := cmd.NewRootCmd(env, opts)
	root.SetArgs(os.Args[1:])
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func fake(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/user":
		w.Header().Set("X-OAuth-Scopes", "gist, read:org, repo, workflow")
		fmt.Fprint(w, `{"login":"you"}`)
	case "/user/repos":
		var repos []string
		for i := range 46 {
			repos = append(repos, fmt.Sprintf(`{"full_name":"acme/service-%d","private":true,"permissions":{"push":true}}`, i))
		}
		repos = append(repos,
			`{"full_name":"acme/payments","private":true,"stargazers_count":12,"permissions":{"admin":true,"push":true}}`,
			`{"full_name":"you/dotfiles","stargazers_count":240,"permissions":{"admin":true,"push":true}}`,
			`{"full_name":"acme/sdk-js","stargazers_count":1830,"permissions":{"push":true}}`)
		fmt.Fprint(w, "["+strings.Join(repos, ",")+"]")
	case "/-/whoami":
		fmt.Fprint(w, `{"username":"you"}`)
	case "/-/npm/v1/tokens":
		fmt.Fprint(w, `{"objects":[]}`)
	case "/-/v1/search":
		fmt.Fprint(w, `{"objects":[{"package":{"name":"@acme/sdk"},"downloads":{"weekly":184000}},
			{"package":{"name":"@acme/cli"},"downloads":{"weekly":41000}},{"package":{"name":"@acme/ui"},"downloads":{"weekly":9800}}]}`)
	case "/auth.test":
		w.Header().Set("X-OAuth-Scopes", "channels:history,groups:history,im:history,chat:write,search:read")
		fmt.Fprint(w, `{"ok":true,"team":"Acme","user":"you"}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
