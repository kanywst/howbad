package cred

import (
	"net/url"
	"regexp"
	"strings"
)

var prefixRules = []struct {
	prefix string
	kind   Kind
}{
	{"github_pat_", GitHub},
	{"ghp_", GitHub},
	{"gho_", GitHub},
	{"ghu_", GitHub},
	{"ghs_", GitHub},
	{"ghr_", GitHub},
	{"npm_", NPM},
	{"xoxe.xoxp-", Slack},
	{"xoxb-", Slack},
	{"xoxp-", Slack},
	{"xoxa-", Slack},
	{"sk-ant-", Anthropic},
	{"sk_live_", Stripe},
	{"rk_live_", Stripe},
	{"glpat-", GitLab},
	{"hf_", HuggingFace},
	{"AIza", GoogleKey},
}

var (
	openaiRe = regexp.MustCompile(`^sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}$`)
	dbRe     = regexp.MustCompile(`^(postgres|postgresql|mysql|mongodb(\+srv)?|redis|rediss)://[^:/@\s]+:\S+@[^/:?@\s]+`)
)

func Classify(name, value string) (Kind, string, bool) {
	v := strings.TrimSpace(value)
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		v = strings.TrimSpace(v[7:])
	}
	if v == "" || IsPlaceholder(v) {
		return "", "", false
	}
	for _, r := range prefixRules {
		if strings.HasPrefix(v, r.prefix) && len(v) >= len(r.prefix)+8 {
			return r.kind, v, true
		}
	}
	if openaiRe.MatchString(v) {
		return OpenAI, v, true
	}
	if dbRe.MatchString(v) {
		return Database, v, true
	}
	if looksSecretName(name) && len(v) >= 16 && !strings.ContainsAny(v, " /\\") {
		return Generic, v, true
	}
	return "", "", false
}

func DatabaseHost(raw string) string {
	// Drivers split on the last @; an unencoded @ in a password is common.
	if _, rest, ok := strings.Cut(raw, "://"); ok {
		raw = rest
	}
	// An unencoded @ may sit in the password or in the query. Parse it both
	// ways and show nothing unless they agree, so no fragment of either
	// is ever printed as a host.
	a, b := hostAfterLastAt(raw), raw
	if i := strings.IndexAny(b, "?#"); i >= 0 {
		b = b[:i]
	}
	if b = hostAfterLastAt(b); a != b {
		return ""
	}
	return a
}

func hostAfterLastAt(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	u, err := url.Parse("x://" + s)
	if err != nil || !hostRe.MatchString(u.Hostname()) {
		return ""
	}
	return u.Hostname()
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9.\-\[\]:,]+$`)

func IsPlaceholder(v string) bool {
	if strings.Contains(v, "${") || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "{env:") ||
		strings.HasPrefix(v, "<") || strings.HasPrefix(v, "op://") {
		return true
	}
	l := strings.ToLower(v)
	for _, p := range []string{"your", "xxxx", "changeme", "example", "placeholder", "redacted", "***", "dummy", "replace"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func looksSecretName(name string) bool {
	n := strings.ToUpper(strings.ReplaceAll(strings.TrimLeft(name, "-"), "-", "_"))
	if n == "" || strings.Contains(n, "PUBLIC") || strings.Contains(n, "PUBLISHABLE") {
		return false
	}
	if n == "TOKEN" || n == "AUTHORIZATION" || n == "PASSWORD" {
		return true
	}
	for _, s := range []string{"_TOKEN", "_KEY", "_SECRET", "_PASSWORD", "_PAT", "APIKEY"} {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}
