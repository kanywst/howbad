package discover

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kanywst/howbad/internal/cred"
)

var awsEnvKeys = map[string]bool{
	"AWS_ACCESS_KEY_ID":     true,
	"AWS_SECRET_ACCESS_KEY": true,
	"AWS_SESSION_TOKEN":     true,
}

var notSecrets = map[string]bool{
	"STARSHIP_SESSION_KEY": true,
	"TERM_SESSION_ID":      true,
	"ITERM_SESSION_ID":     true,
	"WT_SESSION":           true,
}

func fromEnv(env Env) []cred.Credential {
	var out []cred.Credential
	for _, k := range sortedKeys(env.Vars) {
		if awsEnvKeys[k] || notSecrets[k] {
			continue
		}
		v := env.Vars[k]
		kind, secret, ok := cred.Classify(k, v)
		if !ok {
			continue
		}
		if kind == cred.Generic && (k == "NPM_TOKEN" || k == "NODE_AUTH_TOKEN") {
			kind = cred.NPM
		}
		if kind == cred.Generic && (k == "GH_TOKEN" || k == "GITHUB_TOKEN" || strings.HasSuffix(k, "ENTERPRISE_TOKEN")) {
			kind = cred.GitHub
		}
		c := cred.New(kind, "$"+k, "environment variable $"+k, secret)
		if kind == cred.GitHub {
			// gh pairs GH_HOST only with the ENTERPRISE variables; GH_TOKEN
			// belongs to github.com or a *.ghe.com tenant.
			host := env.Vars["GH_HOST"]
			if !enterpriseName(k) && !strings.HasSuffix(normalizeHost(host), ".ghe.com") {
				host = ""
			}
			c.Ref = githubHostRef(k, host)
		}
		out = append(out, c)
	}
	if p := env.Vars["GOOGLE_APPLICATION_CREDENTIALS"]; p != "" && exists(p) {
		out = append(out, cred.Credential{
			Kind:    cred.GCP,
			Via:     "$GOOGLE_APPLICATION_CREDENTIALS",
			Sources: []string{env.tilde(p)},
			Ref:     map[string]string{"keyfile": "true"},
		})
	}
	if id, sec := env.Vars["AWS_ACCESS_KEY_ID"], env.Vars["AWS_SECRET_ACCESS_KEY"]; id != "" && sec != "" {
		out = append(out, cred.NewAWSStatic("$AWS_ACCESS_KEY_ID", "environment variables", id, sec, env.Vars["AWS_SESSION_TOKEN"]))
	}
	return out
}

func ghConfigDir(env Env) string {
	if d := env.Vars["GH_CONFIG_DIR"]; d != "" {
		return d
	}
	if d := env.Vars["XDG_CONFIG_HOME"]; d != "" {
		return filepath.Join(d, "gh")
	}
	return filepath.Join(env.Home, ".config", "gh")
}

func fromGH(ctx context.Context, env Env) []cred.Credential {
	path := filepath.Join(ghConfigDir(env), "hosts.yml")
	data, err := readConfig(path)
	if err != nil {
		return nil
	}
	var hosts map[string]struct {
		OAuthToken string `yaml:"oauth_token"`
	}
	if yaml.Unmarshal(data, &hosts) != nil {
		return nil
	}
	var out []cred.Credential
	for _, host := range sortedKeys(hosts) {
		tok, src := hosts[host].OAuthToken, env.tilde(path)
		if tok == "" && env.Exec != nil {
			if s, err := env.Exec(ctx, "gh", "auth", "token", "--hostname", host); err == nil {
				tok, src = strings.TrimSpace(s), "OS keychain via `gh auth token`"
			}
		}
		if tok == "" {
			continue
		}
		c := cred.New(cred.GitHub, "gh CLI", src, tok)
		c.Ref = map[string]string{"host": normalizeHost(host)}
		out = append(out, c)
	}
	return out
}

func fromNPM(env Env) []cred.Credential {
	userrc := env.Vars["NPM_CONFIG_USERCONFIG"]
	if userrc == "" {
		userrc = filepath.Join(env.Home, ".npmrc")
	}
	paths := []string{userrc}
	if env.Cwd != "" && env.Cwd != env.Home {
		paths = append(paths, filepath.Join(env.Cwd, ".npmrc"))
	}
	var out []cred.Credential
	for pi, p := range paths {
		// A cloned repo's .npmrc must not pull env vars into a credential.
		expand := pi == 0
		data, err := readConfig(p)
		if err != nil {
			continue
		}
		users := map[string]string{}
		type entry struct{ registry, key, val string }
		var entries []entry
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "//") {
				continue
			}
			lhs, val, ok := strings.Cut(line, "=")
			i := strings.LastIndex(lhs, ":")
			if !ok || i < 0 {
				continue
			}
			registry, key := strings.TrimSuffix(lhs[2:i], "/"), strings.TrimSpace(lhs[i+1:])
			if !registryRe.MatchString(registry) {
				continue
			}
			val = strings.Trim(strings.TrimSpace(val), `"'`)
			if strings.HasPrefix(val, "${") && strings.HasSuffix(val, "}") {
				if !expand {
					continue
				}
				val = env.Vars[val[2:len(val)-1]]
			}
			if key == "username" {
				users[registry] = val
				continue
			}
			entries = append(entries, entry{registry, key, val})
		}
		for _, e := range entries {
			if e.val == "" || cred.IsPlaceholder(e.val) {
				continue
			}
			ref := map[string]string{"registry": "https://" + e.registry}
			secret := e.val
			switch e.key {
			case "_authToken":
			case "_auth":
				ref["scheme"] = "basic"
			case "_password":
				pw, err := base64.StdEncoding.DecodeString(e.val)
				if err != nil || users[e.registry] == "" {
					continue
				}
				secret = base64.StdEncoding.EncodeToString([]byte(users[e.registry] + ":" + string(pw)))
				ref["scheme"] = "basic"
			default:
				continue
			}
			// GitHub Packages takes a GitHub PAT, whose reach is GitHub's.
			if kind, _, _ := cred.Classify("", secret); kind == cred.GitHub {
				c := cred.New(cred.GitHub, "npm (GitHub Packages)", env.tilde(p), secret)
				c.Ref = map[string]string{"host": githubPackagesHost(e.registry)}
				c.RepoLocal = pi > 0
				out = append(out, c)
				continue
			}
			c := cred.New(cred.NPM, "npm", env.tilde(p), secret)
			c.Ref = ref
			c.RepoLocal = pi > 0
			out = append(out, c)
		}
	}
	return out
}

func githubPackagesHost(registry string) string {
	host, path, _ := strings.Cut(registry, "/")
	host = strings.Split(host, ":")[0]
	switch {
	case host == "npm.pkg.github.com":
		return "github.com"
	case strings.HasPrefix(host, "npm.pkg.") && strings.HasSuffix(host, ".ghe.com"):
		return strings.TrimPrefix(host, "npm.pkg.")
	case strings.HasPrefix(host, "npm."):
		return strings.TrimPrefix(host, "npm.")
	case strings.HasPrefix(path, "_registry/npm"):
		return host
	}
	return "unknown-enterprise"
}

type awsProfile struct {
	kv      map[string]string
	sources []string
}

func (p *awsProfile) get(k string) string { return p.kv[k] }

var registryRe = regexp.MustCompile(`^[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~%/-]*)?$`)

func fromAWS(env Env) []cred.Credential {
	cfgPath := env.Vars["AWS_CONFIG_FILE"]
	if cfgPath == "" {
		cfgPath = filepath.Join(env.Home, ".aws", "config")
	}
	credPath := env.Vars["AWS_SHARED_CREDENTIALS_FILE"]
	if credPath == "" {
		credPath = filepath.Join(env.Home, ".aws", "credentials")
	}
	profiles := map[string]*awsProfile{}
	var order []string
	add := func(name string, kv map[string]string, src string) {
		p, ok := profiles[name]
		if !ok {
			p = &awsProfile{kv: map[string]string{}}
			profiles[name] = p
			order = append(order, name)
		}
		for k, v := range kv {
			p.kv[k] = v
		}
		p.sources = append(p.sources, env.tilde(src))
	}
	cfg, cfgOrder := parseINI(cfgPath)
	for _, sec := range cfgOrder {
		switch {
		case sec == "default":
			add("default", cfg[sec], cfgPath)
		case strings.HasPrefix(sec, "profile "):
			add(strings.TrimSpace(strings.TrimPrefix(sec, "profile ")), cfg[sec], cfgPath)
		}
	}
	creds, credOrder := parseINI(credPath)
	for _, sec := range credOrder {
		add(sec, creds[sec], credPath)
	}

	var out []cred.Credential
	for _, name := range order {
		p := profiles[name]
		auth := ""
		switch {
		case p.kv["sso_session"] != "" || p.kv["sso_start_url"] != "":
			auth = "sso"
		case p.kv["role_arn"] != "":
			auth = "assume-role"
		case p.kv["credential_process"] != "":
			auth = "credential_process"
		case p.kv["aws_access_key_id"] != "":
			auth = "static"
		case p.kv["web_identity_token_file"] != "":
			auth = "web-identity"
		default:
			continue // region-only profile, nothing to authenticate with
		}
		ref := map[string]string{"profile": name, "auth": auth}
		if runsHelper(profiles, name) {
			ref["exec"] = "credential_process"
		}
		if r := p.kv["sso_role_name"]; r != "" {
			ref["role"] = r
		}
		if a := p.kv["sso_account_id"]; a != "" {
			ref["account"] = a
		}
		if arn := p.kv["role_arn"]; arn != "" {
			ref["role"] = arn[strings.LastIndex(arn, "/")+1:]
			if parts := strings.Split(arn, ":"); len(parts) > 4 {
				ref["account"] = parts[4]
			}
		}
		out = append(out, cred.Credential{
			Kind:    cred.AWS,
			Via:     "AWS profile " + name,
			Sources: p.sources,
			Ref:     ref,
		})
	}
	return out
}

// An unresolvable source_profile chain counts as running a helper.
func runsHelper[P interface{ get(string) string }](profiles map[string]P, name string) bool {
	seen := map[string]bool{}
	for name != "" {
		if seen[name] {
			return true
		}
		seen[name] = true
		p, ok := profiles[name]
		if !ok {
			return true
		}
		if p.get("credential_process") != "" {
			return true
		}
		name = p.get("source_profile")
	}
	return false
}

func fromKube(env Env) []cred.Credential {
	var paths []string
	if kc := env.Vars["KUBECONFIG"]; kc != "" {
		paths = filepath.SplitList(kc)
	} else {
		paths = []string{filepath.Join(env.Home, ".kube", "config")}
	}
	var out []cred.Credential
	for _, p := range paths {
		data, err := readConfig(p)
		if err != nil {
			continue
		}
		cfg, err := clientcmd.Load(data)
		if err != nil {
			continue
		}
		for _, name := range sortedKeys(cfg.Contexts) {
			kctx := cfg.Contexts[name]
			ref := map[string]string{"context": name, "kubeconfig": p, "cluster": kctx.Cluster, "namespace": kctx.Namespace}
			if cl, ok := cfg.Clusters[kctx.Cluster]; ok {
				ref["server"] = cred.RedactURLs(cl.Server)
			}
			if ai, ok := cfg.AuthInfos[kctx.AuthInfo]; ok && ai.Exec != nil {
				ref["exec"] = ai.Exec.Command
			}
			out = append(out, cred.Credential{
				Kind:    cred.Kube,
				Via:     "kube context " + name,
				Sources: []string{env.tilde(p)},
				Ref:     ref,
			})
		}
	}
	return out
}

func fromGCP(env Env) []cred.Credential {
	dir := env.Vars["CLOUDSDK_CONFIG"]
	if dir == "" {
		dir = filepath.Join(env.Home, ".config", "gcloud")
	}
	var out []cred.Credential
	active := "default"
	if b, err := readConfig(filepath.Join(dir, "active_config")); err == nil && strings.TrimSpace(string(b)) != "" {
		active = strings.TrimSpace(string(b))
	}
	cfgPath := filepath.Join(dir, "configurations", "config_"+active)
	if ini, _ := parseINI(cfgPath); ini != nil {
		if acct := ini["core"]["account"]; acct != "" {
			out = append(out, cred.Credential{
				Kind:    cred.GCP,
				Via:     "gcloud " + acct,
				Sources: []string{env.tilde(cfgPath)},
				Ref:     map[string]string{"account": acct, "project": ini["core"]["project"]},
			})
		}
	}
	adc := filepath.Join(dir, "application_default_credentials.json")
	if exists(adc) {
		out = append(out, cred.Credential{
			Kind:    cred.GCP,
			Via:     "Google Application Default Credentials",
			Sources: []string{env.tilde(adc)},
			Ref:     map[string]string{"adc": "true"},
		})
	}
	return out
}
