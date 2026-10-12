package resolve

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

func npm(ctx context.Context, c cred.Credential, o Options) finding.Finding {
	f := finding.Finding{Credential: c}
	registry := strings.TrimSuffix(o.NPMRegistry, "/")
	r := c.Ref["registry"]
	if u, err := url.Parse(r); r != "" && (err != nil || u.Hostname() != "registry.npmjs.org") {
		f.Status = finding.Unverified
		f.Detail = "private registry " + r + " is not checked"
		f.Add(finding.High, "publish to the private npm registry "+r)
		return f
	}
	// Unprefixed tokens may belong to Artifactory or Nexus.
	if r == "" && !strings.HasPrefix(c.Secret(), "npm_") {
		f.Status = finding.Unverified
		f.Detail = "npm-style token for an unknown registry; not sent anywhere"
		f.Add(finding.High, "publish packages to whichever registry issued this token")
		return f
	}
	auth := map[string]string{"Authorization": "Bearer " + c.Secret()}
	if c.Ref["scheme"] == "basic" {
		auth["Authorization"] = "Basic " + c.Secret()
	}

	var who struct {
		Username string `json:"username"`
	}
	_, status, err := getJSON(ctx, o.HTTP, registry+"/-/whoami", auth, &who)
	if err != nil {
		return netFailure(f, err)
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		f.Status, f.Detail = finding.Invalid, "npm rejected the token (revoked or expired)"
		return f
	}
	if status/100 != 2 || who.Username == "" {
		f.Status, f.Detail = finding.Error, fmt.Sprintf("whoami returned %d", status)
		return f
	}
	f.Status, f.Identity = finding.OK, who.Username+" on npm"

	pkgs, err := npmPackages(ctx, o, registry, who.Username)
	if err != nil {
		f.Status, f.Detail = finding.Partial, "could not list packages"
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.Critical, What: "publish new versions of every package " + who.Username + " maintains unless npm demands 2FA", Inferred: true})
		return f
	}
	if len(pkgs) == 0 {
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.Medium, What: "publish new packages as " + who.Username, Inferred: true})
		return f
	}
	sort.SliceStable(pkgs, func(i, j int) bool { return pkgs[i].weekly > pkgs[j].weekly })
	total := 0
	var ex []string
	for i, p := range pkgs {
		total += p.weekly
		if i < 3 && p.weekly > 0 {
			ex = append(ex, fmt.Sprintf("%s (%s/week)", p.name, human(p.weekly)))
		} else if i < 3 {
			ex = append(ex, p.name)
		}
	}
	what := "publish new versions of " + plural(len(pkgs), "npm package", "npm packages")
	if total > 0 {
		what += fmt.Sprintf(" (%s downloads/week)", human(total))
	}
	// A token cannot read back its own permissions: this is an upper bound.
	what += " unless npm demands 2FA"
	f.Reach = append(f.Reach, finding.Capability{Severity: finding.Critical, What: what, Examples: ex, Inferred: true})
	return f
}

type npmPkg struct {
	name   string
	weekly int
}

func npmPackages(ctx context.Context, o Options, registry, user string) ([]npmPkg, error) {
	var res struct {
		Objects []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Downloads struct {
				Weekly int `json:"weekly"`
			} `json:"downloads"`
		} `json:"objects"`
	}
	u := registry + "/-/v1/search?size=250&text=" + url.QueryEscape("maintainer:"+user)
	_, status, err := getJSON(ctx, o.HTTP, u, nil, &res)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("search returned %d", status)
	}
	var out []npmPkg
	for _, ob := range res.Objects {
		out = append(out, npmPkg{ob.Package.Name, ob.Downloads.Weekly})
	}
	return out, nil
}

func human(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%dk", n/1000)
	case n >= 1000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return fmt.Sprintf("%d", n)
}
