package resolve

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

var slackDead = map[string]bool{
	"invalid_auth": true, "not_authed": true, "token_revoked": true,
	"token_expired": true, "account_inactive": true,
}

func slack(ctx context.Context, c cred.Credential, o Options) finding.Finding {
	f := finding.Finding{Credential: c}
	var res struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Team  string `json:"team"`
		User  string `json:"user"`
	}
	hdr, status, err := getJSON(ctx, o.HTTP, strings.TrimSuffix(o.SlackAPI, "/")+"/auth.test",
		map[string]string{"Authorization": "Bearer " + c.Secret()}, &res)
	if err != nil {
		return netFailure(f, err)
	}
	if status/100 != 2 {
		f.Status, f.Detail = finding.Error, fmt.Sprintf("auth.test returned %d", status)
		return f
	}
	if !res.OK {
		f.Status, f.Detail = finding.Error, "auth.test: "+res.Error
		if slackDead[res.Error] {
			f.Status = finding.Invalid
		}
		return f
	}
	f.Status, f.Identity = finding.OK, res.User+" in Slack workspace "+res.Team

	scopes := map[string]bool{}
	for _, s := range strings.Split(hdr.Get("X-OAuth-Scopes"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			scopes[s] = true
		}
	}
	var history []string
	for _, s := range []struct{ scope, label string }{
		{"channels:history", "public channels"},
		{"groups:history", "private channels"},
		{"im:history", "DMs"},
		{"mpim:history", "group DMs"},
	} {
		if scopes[s.scope] {
			history = append(history, s.label)
		}
	}
	var admin []string
	for s := range scopes {
		if strings.HasPrefix(s, "admin") {
			admin = append(admin, s)
		}
	}
	if len(admin) > 0 {
		sort.Strings(admin)
		f.Add(finding.Critical, "administer the "+res.Team+" Slack workspace ("+strings.Join(admin, ", ")+")")
	}
	if len(history) > 0 {
		f.Add(finding.High, "read message history in "+res.Team+": "+strings.Join(history, ", "))
	}
	if scopes["search:read"] {
		f.Add(finding.High, "search every message "+res.User+" can see in "+res.Team)
	}
	if scopes["chat:write"] {
		f.Add(finding.High, "post messages as "+res.User+" in "+res.Team+" (trusted-sender phishing)")
	}
	if scopes["files:read"] {
		f.Add(finding.High, "download files shared in "+res.Team)
	}
	if scopes["users:read.email"] {
		f.Add(finding.Medium, "export the email address of everyone in "+res.Team)
	}
	if len(f.Reach) == 0 {
		f.Add(finding.Medium, "act as "+res.User+" in "+res.Team+" (scopes not reported)")
	}
	return f
}
