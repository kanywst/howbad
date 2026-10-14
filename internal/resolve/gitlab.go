package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

func gitlab(ctx context.Context, c cred.Credential, o Options) finding.Finding {
	f := finding.Finding{Credential: c}
	base, host := strings.TrimSuffix(o.GitLabAPI, "/"), "gitlab.com"
	if h := c.Ref["host"]; h != "" && h != "gitlab.com" {
		if h == "unknown-self-managed" {
			f.Status, f.Detail = finding.Unverified, "self-managed GitLab URL could not be read; not sent anywhere"
			f.Add(finding.High, "use a self-managed GitLab token (host unknown, not checked)")
			return f
		}
		if c.RepoLocal {
			// A cloned repo names this host; don't let it make howbad dial out.
			f.Status, f.Detail = finding.Unverified, "token and host both come from a repo-local config; not sent"
			f.Add(finding.High, "use a GitLab token for "+h+" (not checked)")
			return f
		}
		base, host = "https://"+h+"/api/v4", h
	}
	// Go drops Authorization on a cross-domain redirect but forwards
	// PRIVATE-TOKEN, so use the Bearer form GitLab also accepts.
	auth := map[string]string{"Authorization": "Bearer " + c.Secret()}

	var tok struct {
		Scopes        []string        `json:"scopes"`
		GranularScope json.RawMessage `json:"granular_scopes"`
		UserID        int             `json:"user_id"`
		Active        *bool           `json:"active"`
		Revoked       bool            `json:"revoked"`
	}
	_, status, err := getJSON(ctx, o.HTTP, base+"/personal_access_tokens/self", auth, &tok)
	if err != nil {
		return netFailure(f, err)
	}
	if status == http.StatusUnauthorized {
		// /self rejects some live non-personal tokens, and the configured
		// host may not be the issuer, so a 401 never proves the token dead.
		_, st, err := getJSON(ctx, o.HTTP, base+"/user", auth, nil)
		if err == nil && st == http.StatusUnauthorized {
			f.Status, f.Detail = finding.Unverified, host+" rejected the token; it may be revoked or issued by another GitLab instance"
			f.Reach = append(f.Reach, finding.Capability{Severity: finding.Critical, What: "push code to every GitLab project the token's owner can write to, on whichever instance issued it", Inferred: true})
			return f
		}
	}
	if status/100 == 2 && (tok.Revoked || (tok.Active != nil && !*tok.Active)) {
		f.Status, f.Detail = finding.Invalid, "GitLab reports the token as inactive"
		return f
	}
	if status/100 != 2 {
		// Older instances and non-personal tokens may not serve /self.
		f.Status, f.Detail = finding.Partial, fmt.Sprintf("GET /personal_access_tokens/self returned %d; scopes unknown", status)
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.Critical, What: "push code to every GitLab project the token's owner can write to on " + host, Inferred: true})
		return f
	}

	var user struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"is_admin"`
	}
	who := fmt.Sprintf("user #%d", tok.UserID)
	known := false
	if _, st, err := getJSON(ctx, o.HTTP, base+"/user", auth, &user); err == nil && st/100 == 2 && user.Username != "" {
		who, known = user.Username, true
	}
	f.Status, f.Identity = finding.OK, who+" on "+host

	if g := strings.TrimSpace(string(tok.GranularScope)); len(tok.Scopes) == 0 || (g != "" && g != "null" && g != "[]") {
		// Fine-grained permissions are not mapped yet: report the owner's reach.
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.Critical, What: "push code to every GitLab project " + who + " can write to (fine-grained or unlisted permissions, not read back)", Inferred: true})
		return f
	}
	gitlabScopes(&f, who, host, tok.Scopes, user.IsAdmin, known)
	return f
}

// known is false when /user could not be read, so admin is unknown.
func gitlabScopes(f *finding.Finding, who, host string, list []string, admin, known bool) {
	scopes := map[string]bool{}
	for _, s := range list {
		scopes[s] = true
	}
	// Only administrators can hold these scopes, whether or not /user said so.
	if scopes["admin_mode"] || scopes["read_service_ping"] {
		admin, known = true, true
	}
	// Without Admin Mode, an admin's api token is already an admin token.
	if admin && (scopes["api"] || scopes["sudo"] || scopes["admin_mode"]) {
		f.Add(finding.Critical, "administer the GitLab instance "+host+" and act as any user")
	} else if scopes["sudo"] {
		f.Add(finding.Critical, "act as any user on "+host+" if "+who+" is an administrator")
	}
	switch {
	case scopes["api"]:
		f.Add(finding.Critical, "push code, edit CI/CD pipelines and variables, and publish packages in every GitLab project "+who+" can write to")
	case scopes["write_repository"]:
		f.Add(finding.Critical, "push code to every GitLab project "+who+" can write to")
	}
	if !scopes["api"] && (scopes["read_api"] || scopes["read_repository"]) {
		if admin {
			// Without Admin Mode an administrator reads every project.
			f.Add(finding.High, "read every private project on the GitLab instance "+host+" (administrator)")
		} else if !known {
			f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, What: "read every private GitLab project " + who + " can see (every project on " + host + " if an administrator)", Inferred: true})
		} else {
			f.Add(finding.High, "read every private GitLab project "+who+" can see")
		}
	}
	if !scopes["api"] && scopes["write_registry"] {
		f.Add(finding.High, "push container images to GitLab registries "+who+" can write to")
	}
	if !scopes["api"] && (scopes["read_registry"] || scopes["read_virtual_registry"]) && !scopes["write_registry"] {
		f.Add(finding.Medium, "pull private container images "+who+" can see")
	}
	if scopes["write_virtual_registry"] {
		f.Add(finding.High, "push and delete container images through the GitLab dependency proxy")
	}
	if scopes["k8s_proxy"] {
		f.Add(finding.High, "call Kubernetes clusters connected to GitLab through the agent for Kubernetes")
	}
	if scopes["create_runner"] || scopes["manage_runner"] {
		f.Add(finding.High, "register or reconfigure GitLab CI runners (see CI job secrets)")
	}
	if scopes["self_rotate"] {
		f.Add(finding.Medium, "rotate this token to outlive its expiry")
	}
	if scopes["ai_features"] {
		f.Add(finding.Low, "use GitLab Duo as "+who+" (code and chat on "+who+"'s AI seat)")
	}
	if scopes["read_service_ping"] {
		f.Add(finding.Low, "download "+host+"'s Service Ping usage data")
	}
	if scopes["read_user"] {
		f.Add(finding.Low, "read "+who+"'s profile, including private email, and list users on "+host)
	}
	var rest []string
	for s := range scopes {
		if !gitlabKnown[s] {
			rest = append(rest, s)
		}
	}
	if len(rest) > 0 {
		sort.Strings(rest)
		f.Add(finding.Medium, "use other GitLab scopes: "+strings.Join(rest, ", "))
	}
	if len(f.Reach) == 0 {
		f.Add(finding.Low, "act as "+who+" on "+host+" (profile and public data only)")
	}
}

var gitlabKnown = map[string]bool{
	"api": true, "read_api": true, "read_repository": true, "write_repository": true,
	"read_registry": true, "write_registry": true, "self_rotate": true,
	"read_virtual_registry": true, "write_virtual_registry": true,
	"create_runner": true, "manage_runner": true, "k8s_proxy": true,
	"admin_mode": true, "sudo": true, "read_user": true, "read_service_ping": true,
	"ai_features": true,
}
