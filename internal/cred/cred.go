package cred

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Kind string

const (
	GitHub      Kind = "github"
	NPM         Kind = "npm"
	Slack       Kind = "slack"
	AWS         Kind = "aws"
	Kube        Kind = "kubernetes"
	GCP         Kind = "gcp"
	OpenAI      Kind = "openai"
	Anthropic   Kind = "anthropic"
	Stripe      Kind = "stripe"
	GitLab      Kind = "gitlab"
	HuggingFace Kind = "huggingface"
	GoogleKey   Kind = "google-api-key"
	Database    Kind = "database"
	Generic     Kind = "secret"
)

var kinds = []Kind{GitHub, NPM, Slack, AWS, Kube, GCP, OpenAI, Anthropic, Stripe, GitLab, HuggingFace, GoogleKey, Database, Generic}

func KindNames() []string {
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = string(k)
	}
	return out
}

func Known(name string) bool {
	for _, k := range kinds {
		if string(k) == name {
			return true
		}
	}
	return false
}

// The secret is unexported so it cannot reach JSON; Format keeps it out of
// format strings.
type Credential struct {
	Kind        Kind              `json:"kind"`
	Via         string            `json:"via"`
	Sources     []string          `json:"sources"`
	HandedTo    []string          `json:"handed_to,omitempty"`
	Ref         map[string]string `json:"ref,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	// RepoLocal: found only in configs inside the current directory, which
	// a cloned repo controls.
	RepoLocal bool `json:"repo_local,omitempty"`

	secret string
}

func New(kind Kind, via, source, secret string) Credential {
	c := Credential{Kind: kind, Via: via, Sources: []string{source}, secret: secret}
	if secret != "" {
		sum := sha256.Sum256([]byte(secret))
		c.Fingerprint = hex.EncodeToString(sum[:])[:8]
	}
	return c
}

func NewAWSStatic(via, source, keyID, secretKey, sessionToken string) Credential {
	c := New(AWS, via, source, keyID+"\x00"+secretKey+"\x00"+sessionToken)
	suffix := keyID
	if len(suffix) > 4 {
		suffix = suffix[len(suffix)-4:]
	}
	c.Ref = map[string]string{"auth": "static", "key_id_suffix": suffix}
	return c
}

func (c Credential) Secret() string { return c.secret }

// Format keeps the secret out of %v, %+v and %#v, which print unexported
// fields, including when a Credential is nested in another struct.
func (c Credential) Format(s fmt.State, verb rune) {
	type plain Credential
	p := plain(c)
	if p.secret != "" {
		p.secret = "[redacted]"
	}
	fmt.Fprintf(s, fmt.FormatString(s, verb), p)
}

func (c Credential) AWSStatic() (keyID, secretKey, sessionToken string, ok bool) {
	parts := strings.Split(c.secret, "\x00")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func (c Credential) key() string {
	if c.secret != "" {
		return string(c.Kind) + ":" + c.Fingerprint
	}
	refKeys := make([]string, 0, len(c.Ref))
	for k := range c.Ref {
		refKeys = append(refKeys, k)
	}
	sort.Strings(refKeys)
	var b strings.Builder
	b.WriteString(string(c.Kind))
	for _, k := range refKeys {
		b.WriteString("|" + k + "=" + c.Ref[k])
	}
	return b.String()
}

func Merge(in []Credential) []Credential {
	var out []Credential
	idx := map[string][]int{}
	for _, c := range in {
		k := c.key()
		i := -1
		// One config must not redirect a secret another config points elsewhere.
		for _, j := range idx[k] {
			if !refConflict(c.Kind, out[j].Ref, c.Ref) {
				i = j
				break
			}
		}
		if i < 0 {
			idx[k] = append(idx[k], len(out))
			out = append(out, c)
			continue
		}
		out[i].RepoLocal = out[i].RepoLocal && c.RepoLocal
		out[i].Sources = union(out[i].Sources, c.Sources)
		out[i].HandedTo = union(out[i].HandedTo, c.HandedTo)
		for rk, rv := range c.Ref {
			if out[i].Ref == nil {
				out[i].Ref = map[string]string{}
			}
			if _, ok := out[i].Ref[rk]; !ok {
				out[i].Ref[rk] = rv
			}
		}
	}
	return out
}

var defaultHost = map[Kind]string{GitHub: "github.com", GitLab: "gitlab.com"}

func refConflict(kind Kind, a, b map[string]string) bool {
	// A token with no host belongs to the public instance, so a repo-local
	// host cannot be merged onto it.
	if def, ok := defaultHost[kind]; ok {
		ha, hb := a["host"], b["host"]
		if ha == "" {
			ha = def
		}
		if hb == "" {
			hb = def
		}
		if ha != hb {
			return true
		}
	}
	for k, v := range a {
		if w, ok := b[k]; ok && w != v {
			return true
		}
	}
	return false
}

var urlUserinfo = regexp.MustCompile(`://[^/@\s]*@`)

// RedactURLs hides userinfo in any URL inside s.
func RedactURLs(s string) string { return urlUserinfo.ReplaceAllString(s, "://***@") }

func union(a, b []string) []string {
	for _, s := range b {
		found := false
		for _, t := range a {
			if s == t {
				found = true
				break
			}
		}
		if !found {
			a = append(a, s)
		}
	}
	return a
}
