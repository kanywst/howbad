package discover

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/kanywst/howbad/internal/cred"
)

type agentFile struct {
	agent   string
	path    string
	toml    bool
	project bool
}

func agentFiles(env Env) []agentFile {
	h, c := env.Home, env.Cwd
	appSupport := filepath.Join(h, ".config")
	if env.GOOS == "darwin" {
		appSupport = filepath.Join(h, "Library", "Application Support")
	}
	files := []agentFile{
		{agent: "Claude Code", path: filepath.Join(h, ".claude.json")},
		{agent: "Claude Code", path: filepath.Join(h, ".claude", "settings.json")},
		{agent: "Claude Desktop", path: filepath.Join(appSupport, "Claude", "claude_desktop_config.json")},
		{agent: "Cursor", path: filepath.Join(h, ".cursor", "mcp.json")},
		{agent: "Windsurf", path: filepath.Join(h, ".codeium", "windsurf", "mcp_config.json")},
		{agent: "Devin Desktop", path: filepath.Join(xdgConfig(env), "devin", "mcp_config.json")},
		{agent: "VS Code", path: filepath.Join(appSupport, "Code", "User", "mcp.json")},
		{agent: "Gemini CLI", path: filepath.Join(h, ".gemini", "settings.json")},
		{agent: "Codex", path: filepath.Join(h, ".codex", "config.toml"), toml: true},
	}
	if c != "" && c != h {
		files = append(files,
			agentFile{agent: "Claude Code", path: filepath.Join(c, ".mcp.json"), project: true},
			agentFile{agent: "Claude Code", path: filepath.Join(c, ".claude", "settings.json"), project: true},
			agentFile{agent: "Claude Code", path: filepath.Join(c, ".claude", "settings.local.json"), project: true},
			agentFile{agent: "Cursor", path: filepath.Join(c, ".cursor", "mcp.json"), project: true},
			agentFile{agent: "VS Code", path: filepath.Join(c, ".vscode", "mcp.json"), project: true},
			agentFile{agent: "Gemini CLI", path: filepath.Join(c, ".gemini", "settings.json"), project: true},
		)
	}
	return files
}

var agentHomes = map[string][]string{
	"Claude Code":   {".claude"},
	"Codex":         {".codex"},
	"Cursor":        {".cursor"},
	"Gemini CLI":    {".gemini"},
	"Windsurf":      {".codeium/windsurf"},
	"Devin Desktop": {".config/devin"},
}

func fromAgents(env Env) ([]cred.Credential, []Agent) {
	var out []cred.Credential
	found := map[string]*Agent{}
	var order []string
	mark := func(name, config string) *Agent {
		a, ok := found[name]
		if !ok {
			a = &Agent{Name: name, Config: config}
			found[name] = a
			order = append(order, name)
		}
		return a
	}

	for _, f := range agentFiles(env) {
		data, err := readConfig(f.path)
		if err != nil {
			continue
		}
		doc := map[string]any{}
		if f.toml {
			if _, err := toml.Decode(string(data), &doc); err != nil {
				continue
			}
		} else if json.Unmarshal(data, &doc) != nil {
			continue
		}
		a := mark(f.agent, env.tilde(f.path))
		// Claude Code ignores bypassPermissions in project settings.
		if p := posture(f.agent, doc); p != "" && !f.project {
			a.Posture = p
		}
		src := env.tilde(f.path)
		srv := servers(doc)
		if !f.project {
			for name, s := range projectServers(env, doc) {
				srv[name] = s
			}
		}
		var found []cred.Credential
		for i, name := range sortedKeys(srv) {
			if i == maxServersPerFile {
				break
			}
			found = append(found, serverCreds(f.agent, name, src, srv[name])...)
		}
		if f.agent == "Claude Code" && strings.Contains(filepath.Base(f.path), "settings") {
			found = append(found, envBlockCreds(f.agent, "Claude Code settings env", src, stringMap(doc["env"]))...)
		}
		for i := range found {
			found[i].RepoLocal = f.project
		}
		out = append(out, found...)
	}
	for _, name := range sortedKeys(agentHomes) {
		for _, d := range agentHomes[name] {
			if exists(filepath.Join(env.Home, d)) {
				mark(name, "")
			}
		}
	}
	agents := make([]Agent, 0, len(order))
	for _, n := range order {
		agents = append(agents, *found[n])
	}
	return out, agents
}

func servers(doc map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, key := range []string{"mcpServers", "servers", "mcp_servers"} {
		m, _ := doc[key].(map[string]any)
		for name, s := range m {
			if sm, ok := s.(map[string]any); ok {
				out[name] = sm
			}
		}
	}
	return out
}

// projectServers reads ~/.claude.json's projects.<path>.mcpServers, one
// level deep only.
func projectServers(env Env, doc map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	projects, _ := doc["projects"].(map[string]any)
	for p, v := range projects {
		pm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for name, s := range servers(pm) {
			out[fmt.Sprintf("%s (project %s)", name, env.tilde(p))] = s
		}
	}
	return out
}

func posture(agent string, doc map[string]any) string {
	switch agent {
	case "Claude Code":
		perms, _ := doc["permissions"].(map[string]any)
		if mode, _ := perms["defaultMode"].(string); mode == "bypassPermissions" {
			return "bypassPermissions"
		}
	case "Codex":
		sandbox, _ := doc["sandbox_mode"].(string)
		approval, _ := doc["approval_policy"].(string)
		if sandbox == "danger-full-access" && approval == "never" {
			return "danger-full-access, never asks"
		}
		if sandbox == "danger-full-access" {
			return "danger-full-access"
		}
	}
	return ""
}

func serverCreds(agent, server, src string, s map[string]any) []cred.Credential {
	via := fmt.Sprintf("MCP server %q (%s)", server, agent)
	var out []cred.Credential
	add := func(name, val string) {
		if kind, secret, ok := cred.Classify(name, val); ok {
			c := cred.New(kind, via, src, secret)
			c.HandedTo = []string{agent}
			out = append(out, c)
		}
	}
	out = append(out, envBlockCreds(agent, via, src, stringMap(s["env"]))...)
	for _, hk := range []string{"headers", "http_headers", "auth"} {
		h := stringMap(s[hk])
		for _, k := range sortedKeys(h) {
			add(k, h[k])
		}
	}
	args := stringSlice(s["args"])
	for i, a := range args {
		switch {
		case strings.Contains(a, "="):
			k, v, _ := strings.Cut(a, "=")
			if isHeader(v) {
				k, v, _ = strings.Cut(v, ":")
			}
			add(k, v)
		case isHeader(a):
			k, v, _ := strings.Cut(a, ":")
			add(k, v)
		case i > 0 && strings.HasPrefix(args[i-1], "-") && !strings.HasPrefix(a, "-"):
			add(args[i-1], a)
		default:
			add("", a)
		}
	}
	for _, uk := range []string{"url", "serverUrl", "httpUrl"} {
		raw, _ := s[uk].(string)
		u, err := url.Parse(raw)
		if raw == "" || err != nil {
			continue
		}
		for k, vs := range u.Query() {
			for _, v := range vs {
				add(k, v)
			}
		}
	}
	return out
}

func envBlockCreds(agent, via, src string, env map[string]string) []cred.Credential {
	var out []cred.Credential
	for _, k := range sortedKeys(env) {
		if awsEnvKeys[k] {
			continue
		}
		kind, secret, ok := cred.Classify(k, env[k])
		if !ok {
			continue
		}
		if kind == cred.Generic && (k == "GITHUB_PERSONAL_ACCESS_TOKEN" || k == "GITHUB_TOKEN" || k == "GH_TOKEN") {
			kind = cred.GitHub
		}
		c := cred.New(kind, via, src, secret)
		c.HandedTo = []string{agent}
		if kind == cred.GitHub {
			c.Ref = githubHostRef(k, env["GITHUB_HOST"], env["GH_HOST"], env["GITHUB_API_URL"])
		}
		if kind == cred.GitLab {
			c.Ref = gitlabHostRef(env)
		}
		out = append(out, c)
	}
	if id, sec := env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"]; id != "" && sec != "" && !cred.IsPlaceholder(id) {
		c := cred.NewAWSStatic(via, src, id, sec, env["AWS_SESSION_TOKEN"])
		c.HandedTo = []string{agent}
		out = append(out, c)
	}
	return out
}

var headerArg = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*:\s*\S`)

func isHeader(s string) bool { return headerArg.MatchString(s) && !strings.Contains(s, "://") }

// githubHostRef keeps Enterprise tokens from being sent to github.com.
func githubHostRef(name string, hosts ...string) map[string]string {
	for _, h := range hosts {
		if h = normalizeHost(h); h != "" {
			if h == "api.github.com" {
				h = "github.com"
			}
			if strings.HasPrefix(h, "api.") && strings.HasSuffix(h, ".ghe.com") {
				h = strings.TrimPrefix(h, "api.")
			}
			return map[string]string{"host": h}
		}
	}
	if enterpriseName(name) {
		return map[string]string{"host": "unknown-enterprise"}
	}
	return nil
}

// gitlabHostRef keeps self-managed tokens from being sent to gitlab.com.
// The variables are the ones glab, the GitLab MCP servers and CI read.
func gitlabHostRef(env map[string]string) map[string]string {
	for _, k := range []string{"GITLAB_API_URL", "GITLAB_URL", "GITLAB_HOST", "CI_SERVER_URL"} {
		v := strings.TrimSpace(env[k])
		if v == "" {
			continue
		}
		h := normalizeHost(v)
		if h == "" && !strings.Contains(v, "://") {
			h = normalizeHost("https://" + v)
		}
		if h == "" {
			// Set but unreadable: never fall back to gitlab.com.
			h = "unknown-self-managed"
		}
		return map[string]string{"host": h}
	}
	return nil
}

var gheName = regexp.MustCompile(`(^|_)GHES?(_|$)|ENTERPRISE`)

func enterpriseName(name string) bool { return gheName.MatchString(strings.ToUpper(name)) }

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if u, err := url.Parse(h); err == nil && u.Host != "" {
		h = u.Host
	}
	h = strings.TrimSuffix(h, "/")
	if strings.ContainsAny(h, "@/ ?#\\") {
		return ""
	}
	return h
}

const maxServersPerFile = 200

func xdgConfig(env Env) string {
	if d := env.Vars["XDG_CONFIG_HOME"]; d != "" {
		return d
	}
	return filepath.Join(env.Home, ".config")
}

func stringMap(v any) map[string]string {
	m, _ := v.(map[string]any)
	out := map[string]string{}
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

func stringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	}
	return nil
}
