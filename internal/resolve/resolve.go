package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

type Options struct {
	HTTP    *http.Client
	Offline bool
	NoExec  bool
	Timeout time.Duration

	GitHubAPI   string
	NPMRegistry string
	SlackAPI    string
}

func (o *Options) defaults() {
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if o.Timeout == 0 {
		o.Timeout = 20 * time.Second
	}
	if o.GitHubAPI == "" {
		o.GitHubAPI = "https://api.github.com"
	}
	if o.NPMRegistry == "" {
		o.NPMRegistry = "https://registry.npmjs.org"
	}
	if o.SlackAPI == "" {
		o.SlackAPI = "https://slack.com/api"
	}
}

type resolver func(ctx context.Context, c cred.Credential, o Options) finding.Finding

var resolvers = map[cred.Kind]resolver{
	cred.GitHub: github,
	cred.NPM:    npm,
	cred.Slack:  slack,
	cred.AWS:    aws,
	cred.Kube:   kube,
}

func All(ctx context.Context, creds []cred.Credential, o Options) []finding.Finding {
	o.defaults()
	out := make([]finding.Finding, len(creds))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				cctx, cancel := context.WithTimeout(ctx, o.Timeout)
				out[i] = One(cctx, creds[i], o)
				cancel()
			}
		}()
	}
	for i := range creds {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

func One(ctx context.Context, c cred.Credential, o Options) finding.Finding {
	r, ok := resolvers[c.Kind]
	if !ok {
		return unverified(c)
	}
	if o.Offline {
		if c.Kind == cred.AWS {
			return awsOffline(c)
		}
		return skippedGuess(finding.Finding{Credential: c, Status: finding.Skipped, Detail: "not checked (--offline)"})
	}
	return r(ctx, c, o)
}

func skippedGuess(f finding.Finding) finding.Finding {
	if what, ok := offlineGuess[f.Credential.Kind]; ok {
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, What: what, Inferred: true})
	}
	return f
}

var offlineGuess = map[cred.Kind]string{
	cred.GitHub: "use a GitHub token as its owner",
	cred.NPM:    "use an npm token as its owner",
	cred.Slack:  "use a Slack token as its owner",
	cred.Kube:   "use a Kubernetes context",
}

func unverified(c cred.Credential) finding.Finding {
	f := finding.Finding{Credential: c, Status: finding.Unverified, Detail: "recognized by format, not checked against the provider"}
	switch c.Kind {
	case cred.Stripe:
		f.Add(finding.Critical, "move money on a live Stripe account (charges, refunds, payouts)")
	case cred.Database:
		what := "connect to a database with a password"
		if h := cred.DatabaseHost(c.Secret()); h != "" {
			what = "connect to database " + h + " with a password"
		}
		f.Add(finding.High, what)
	case cred.GitLab:
		f.Add(finding.High, "use the GitLab API as you (scopes not checked yet)")
	case cred.GCP:
		what := "use Google Cloud as " + c.Ref["account"]
		if p := c.Ref["project"]; p != "" {
			what += " (project " + p + ")"
		}
		if c.Ref["adc"] == "true" {
			what = "use Google Cloud via Application Default Credentials (any SDK picks them up)"
		}
		if c.Ref["keyfile"] == "true" {
			what = "use Google Cloud as the service account in $GOOGLE_APPLICATION_CREDENTIALS"
		}
		f.Add(finding.High, what+"; roles not checked yet")
	case cred.OpenAI:
		f.Add(finding.Medium, "spend money on your OpenAI API account")
	case cred.Anthropic:
		f.Add(finding.Medium, "spend money on your Anthropic API account")
	case cred.GoogleKey:
		f.Add(finding.Medium, "spend money on a Google API key (Gemini, Maps, Cloud APIs)")
	case cred.HuggingFace:
		f.Add(finding.Medium, "use Hugging Face as you (private models and datasets)")
	default:
		f.Add(finding.Low, "use an unrecognized secret ("+c.Via+")")
	}
	return f
}

func getJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, out any) (http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "howbad")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return resp.Header, resp.StatusCode, err
	}
	if resp.StatusCode/100 == 2 && out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return resp.Header, resp.StatusCode, fmt.Errorf("decoding %s: %w", req.URL.Path, err)
		}
	}
	return resp.Header, resp.StatusCode, nil
}

func netFailure(f finding.Finding, err error) finding.Finding {
	f.Status = finding.Unreachable
	f.Detail = err.Error()
	return f
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func looksProd(names ...string) bool {
	for _, n := range names {
		l := strings.ToLower(n)
		if strings.Contains(l, "prod") || strings.Contains(l, "prd") || strings.Contains(l, "live") {
			return true
		}
	}
	return false
}
