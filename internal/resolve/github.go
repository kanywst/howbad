package resolve

import (
	"context"
	"fmt"
	"net/http"
	neturl "net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

type ghRepo struct {
	FullName    string `json:"full_name"`
	Private     bool   `json:"private"`
	Archived    bool   `json:"archived"`
	Stars       int    `json:"stargazers_count"`
	Permissions struct {
		Admin bool `json:"admin"`
		Push  bool `json:"push"`
		Pull  bool `json:"pull"`
	} `json:"permissions"`
}

const ghMaxPages = 10

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func github(ctx context.Context, c cred.Credential, o Options) finding.Finding {
	f := finding.Finding{Credential: c}
	base, host := o.GitHubAPI, "github.com"
	switch h := c.Ref["host"]; {
	case c.RepoLocal && h != "" && h != "github.com":
		// A cloned repo names this host; don't let it make howbad dial out.
		f.Status, f.Detail = finding.Unverified, "token and host both come from a repo-local config; not sent"
		f.Add(finding.High, "use a GitHub token for "+h+" (not checked)")
		return f
	case h == "unknown-enterprise":
		f.Status, f.Detail = finding.Unverified, "GitHub Enterprise token with no host configured; not sent anywhere"
		f.Add(finding.High, "use a GitHub Enterprise token (host unknown, not checked)")
		return f
	case strings.HasSuffix(h, ".ghe.com"):
		base, host = "https://api."+h, h
	case h != "" && h != "github.com":
		base, host = "https://"+h+"/api/v3", h
	}
	auth := map[string]string{"Authorization": "Bearer " + c.Secret()}

	var user struct {
		Login string `json:"login"`
	}
	hdr, status, err := getJSON(ctx, o.HTTP, base+"/user", auth, &user)
	if err != nil {
		return netFailure(f, err)
	}
	if status == http.StatusUnauthorized {
		f.Status, f.Detail = finding.Invalid, "GitHub rejected the token (revoked or expired)"
		return f
	}
	if status == http.StatusForbidden && strings.HasPrefix(c.Secret(), "ghs_") {
		return ghInstallation(ctx, o, base, host, auth, f)
	}
	if status/100 != 2 {
		f.Status, f.Detail = finding.Error, fmt.Sprintf("GET /user returned %d", status)
		return f
	}
	f.Status, f.Identity = finding.OK, user.Login+" on "+host

	scopes := map[string]bool{}
	for _, s := range strings.Split(hdr.Get("X-OAuth-Scopes"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			scopes[s] = true
		}
	}
	// Fine-grained and app tokens send no scopes (ghu_ sends an empty header),
	// so their repo permissions are the user's role: an upper bound.
	tok := c.Secret()
	classic := len(scopes) > 0 || strings.HasPrefix(tok, "ghp_") || strings.HasPrefix(tok, "gho_")
	upper := !classic
	canWrite := func(r ghRepo) bool {
		if r.Archived || !r.Permissions.Push {
			return false
		}
		if !classic {
			return true
		}
		return scopes["repo"] || (scopes["public_repo"] && !r.Private)
	}

	repos, truncated, err := ghRepos(ctx, o, base+"/user/repos?per_page=100&sort=pushed", auth)
	if err != nil {
		f.Status, f.Detail = finding.Partial, "could not list every repository"
		truncated = true
	}
	var push, admin []ghRepo
	privateRead := 0
	for _, r := range repos {
		if canWrite(r) {
			push = append(push, r)
			if r.Permissions.Admin {
				admin = append(admin, r)
			}
		}
		if r.Private && (!classic || scopes["repo"]) {
			privateRead++
		}
	}
	more := ""
	if truncated {
		more = "+"
	}
	qual := ""
	if upper {
		qual = "up to "
	}

	if err != nil && len(push) == 0 && (!classic || scopes["repo"] || scopes["public_repo"]) {
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.Critical, What: "push code to every repo " + user.Login + " can write to", Inferred: true})
	}
	if len(push) > 0 {
		what := fmt.Sprintf("push code to %s%d%s GitHub repos", qual, len(push), more)
		if !classic || scopes["workflow"] {
			what += " and rewrite their CI workflows"
		}
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.Critical, What: what, Examples: topRepos(push, 3), Inferred: upper})
	}
	if len(admin) > 0 {
		f.Reach = append(f.Reach, finding.Capability{
			Severity: finding.High,
			What:     fmt.Sprintf("change settings on %s%d repos (branch protection, deploy keys, webhooks)", qual, len(admin)),
			Inferred: upper,
		})
	}
	if privateRead > 0 && len(push) == 0 {
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, What: fmt.Sprintf("read %s%d private repos", qual, privateRead), Inferred: upper})
	}
	if scopes["delete_repo"] {
		f.Add(finding.Critical, "delete repositories")
	}
	if scopes["admin:org"] || scopes["write:org"] {
		orgs, ok := ghAdminOrgs(ctx, o, base, auth)
		if !ok {
			f.Status, f.Detail = finding.Partial, "could not list org memberships"
		}
		if len(orgs) > 0 {
			f.Add(finding.Critical, "administer GitHub orgs as owner", orgs...)
		}
	}
	if scopes["write:packages"] {
		f.Add(finding.High, "publish GitHub Packages (containers, npm, Maven)")
	}
	if scopes["gist"] {
		f.Add(finding.Medium, "create secret gists, a ready-made exfiltration channel")
	}
	if len(f.Reach) == 0 && f.Status == finding.OK {
		f.Add(finding.Low, "act as "+user.Login+" on GitHub (public data only)")
	}
	return f
}

// Installation tokens (Actions' GITHUB_TOKEN) cannot call /user.
func ghInstallation(ctx context.Context, o Options, base, host string, auth map[string]string, f finding.Finding) finding.Finding {
	var res struct {
		Total int      `json:"total_count"`
		Repos []ghRepo `json:"repositories"`
	}
	_, status, err := getJSON(ctx, o.HTTP, base+"/installation/repositories?per_page=100", auth, &res)
	if err != nil {
		return netFailure(f, err)
	}
	if status/100 != 2 {
		f.Status, f.Detail = finding.Error, fmt.Sprintf("GET /installation/repositories returned %d", status)
		return f
	}
	f.Status, f.Identity = finding.OK, "GitHub App installation on "+host
	n := max(res.Total, len(res.Repos))
	if n > 0 {
		f.Reach = append(f.Reach, finding.Capability{
			Severity: finding.Critical,
			What:     fmt.Sprintf("push code to up to %d GitHub repos (app installation token)", n),
			Examples: topRepos(res.Repos, 3),
			Inferred: true,
		})
	}
	return f
}

func ghRepos(ctx context.Context, o Options, url string, auth map[string]string) ([]ghRepo, bool, error) {
	var all []ghRepo
	origin := originOf(url)
	for page := 0; url != ""; page++ {
		if page == ghMaxPages {
			return all, true, nil
		}
		if originOf(url) != origin {
			return all, true, nil
		}
		var batch []ghRepo
		hdr, status, err := getJSON(ctx, o.HTTP, url, auth, &batch)
		if err != nil {
			return all, false, err
		}
		if status/100 != 2 {
			return all, false, fmt.Errorf("GET /user/repos returned %d", status)
		}
		all = append(all, batch...)
		url = ""
		if m := linkNext.FindStringSubmatch(hdr.Get("Link")); m != nil {
			url = m[1]
		}
	}
	return all, false, nil
}

func ghAdminOrgs(ctx context.Context, o Options, base string, auth map[string]string) ([]string, bool) {
	var ms []struct {
		Role string `json:"role"`
		Org  struct {
			Login string `json:"login"`
		} `json:"organization"`
	}
	if _, status, err := getJSON(ctx, o.HTTP, base+"/user/memberships/orgs?state=active&per_page=100", auth, &ms); err != nil || status/100 != 2 {
		return nil, false
	}
	var out []string
	for _, m := range ms {
		if m.Role == "admin" {
			out = append(out, m.Org.Login)
		}
	}
	return out, true
}

func originOf(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func topRepos(rs []ghRepo, n int) []string {
	sorted := append([]ghRepo(nil), rs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Stars > sorted[j].Stars })
	var out []string
	for i := 0; i < len(sorted) && i < n; i++ {
		s := sorted[i].FullName
		if sorted[i].Stars > 0 {
			s += fmt.Sprintf(" (%d★)", sorted[i].Stars)
		}
		out = append(out, s)
	}
	return out
}
