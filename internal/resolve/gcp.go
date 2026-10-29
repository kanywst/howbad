package resolve

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

// gcpChecks are tested with projects.testIamPermissions, which answers for
// the caller only and includes roles inherited from folders, the
// organization and groups.
var gcpChecks = []struct {
	sev   finding.Severity
	what  string
	perms []string
}{
	{finding.Critical, "grant anyone any role (owner-level control) on", []string{"resourcemanager.projects.setIamPolicy"}},
	{finding.Critical, "act as service accounts (mint keys or tokens) in", []string{"iam.serviceAccountKeys.create", "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signJwt", "iam.serviceAccounts.actAs"}},
	{finding.High, "read Secret Manager secrets in", []string{"secretmanager.versions.access"}},
	{finding.High, "get credentials for GKE clusters in", []string{"container.clusters.getCredentials"}},
	{finding.High, "run code and spend money (VMs, Cloud Run, Functions) in", []string{"compute.instances.create", "run.services.create", "cloudfunctions.functions.create"}},
	{finding.High, "read data (Cloud Storage, BigQuery, Cloud SQL) in", []string{"storage.objects.get", "bigquery.tables.getData", "cloudsql.instances.connect"}},
	{finding.High, "delete data or whole projects in", []string{"storage.objects.delete", "storage.buckets.delete", "resourcemanager.projects.delete"}},
}

const maxGCPProjects = 25

// knownGoogleTypes are echoed in Detail; anything else in the file is not.
var knownGoogleTypes = map[string]bool{
	"external_account":                 true,
	"external_account_authorized_user": true,
	"impersonated_service_account":     true,
	"gdch_service_account":             true,
}

type googleKey struct {
	Type           string `json:"type"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	RefreshToken   string `json:"refresh_token"`
	ClientEmail    string `json:"client_email"`
	PrivateKey     string `json:"private_key"`
	PrivateKeyID   string `json:"private_key_id"`
	ProjectID      string `json:"project_id"`
	QuotaProjectID string `json:"quota_project_id"`
}

func gcp(ctx context.Context, c cred.Credential, o Options) finding.Finding {
	f := finding.Finding{Credential: c}
	if c.Secret() == "" {
		if c.Ref["account"] != "" && o.NoExec {
			f.Status, f.Detail = finding.Skipped, "needs `gcloud auth print-access-token` (skipped by --no-exec)"
		} else {
			f.Status, f.Detail = finding.Unverified, "no token could be read"
		}
		return gcpGuess(f)
	}

	var key googleKey
	token := ""
	switch {
	case c.Ref["account"] != "":
		token = c.Secret()
	case json.Unmarshal([]byte(c.Secret()), &key) != nil:
		f.Status, f.Detail = finding.Unverified, "credential file is not valid JSON"
		return gcpGuess(f)
	case key.Type == "authorized_user" || key.Type == "service_account":
		var err error
		token, err = googleToken(ctx, o, key)
		var unchecked *googleUnchecked
		switch {
		case errors.Is(err, errGoogleRejected):
			f.Status, f.Detail = finding.Expired, "Google rejected it (revoked or expired; log in again)"
			return f
		case errors.As(err, &unchecked):
			f.Status, f.Detail = finding.Unverified, unchecked.why
			return gcpGuess(f)
		case err != nil:
			return gcpGuess(netFailure(f, err))
		}
	default:
		// external_account can run a program and impersonation chains go
		// through other credentials; neither is exchanged here.
		what := "this credential type"
		if knownGoogleTypes[key.Type] {
			what = key.Type
		}
		f.Status, f.Detail = finding.Unverified, what+" is not checked"
		return gcpGuess(f)
	}

	auth := map[string]string{"Authorization": "Bearer " + token}
	// gcloud hands out the impersonated account's token when configured to.
	for _, id := range []string{c.Ref["impersonate"], key.ClientEmail, c.Ref["account"]} {
		if id != "" {
			f.Identity = id
			break
		}
	}
	if f.Identity == "" {
		f.Identity = googleEmail(ctx, o, token)
	}

	listed, complete, code, err := listGCPProjects(ctx, o, auth)
	if err != nil {
		return gcpGuess(netFailure(f, err))
	}
	if code == http.StatusUnauthorized {
		f.Status, f.Detail = finding.Expired, "Google rejected the token (expired; log in again)"
		return f
	}
	visible := map[string]bool{}
	for _, p := range listed {
		visible[p] = true
	}
	var projects []string
	seen := map[string]bool{}
	for _, p := range append([]string{c.Ref["project"], key.ProjectID, key.QuotaProjectID}, listed...) {
		if p != "" && !seen[p] {
			seen[p] = true
			projects = append(projects, p)
		}
	}
	f.Status = finding.OK
	listOK := code/100 == 2
	if !listOK {
		f.Status, f.Detail = finding.Partial, fmt.Sprintf("could not list projects (HTTP %d)", code)
	} else if !complete {
		f.Status, f.Detail = finding.Partial, "the project list was cut short"
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, Inferred: true,
			What: "use more Google Cloud projects than could be listed"})
	}
	if len(projects) == 0 {
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, Inferred: true,
			What: "use Google Cloud as " + f.Identity + "; no project visible to check"})
		return f
	}

	granted := map[int][]string{}
	checked, failed, getOnly := 0, 0, []string{}
	for i, p := range projects {
		if i == maxGCPProjects {
			failed += len(projects) - maxGCPProjects
			break
		}
		if ctx.Err() != nil {
			failed += len(projects) - i
			break
		}
		have, code, err := testGCPPermissions(ctx, o, auth, p)
		// Only a 404 on a project no listing showed means there is nothing
		// there. A 403 can be narrowed scopes, a disabled API or VPC-SC, so
		// it stays unchecked even for a project named only in a config.
		if err == nil && code == http.StatusNotFound && !visible[p] && listOK {
			continue
		}
		if err != nil || code/100 != 2 {
			failed++
			continue
		}
		checked++
		hit := false
		for j, chk := range gcpChecks {
			for _, perm := range chk.perms {
				if have[perm] {
					granted[j] = append(granted[j], p)
					hit = true
					break
				}
			}
		}
		if !hit && have["resourcemanager.projects.get"] {
			getOnly = append(getOnly, p)
		}
	}
	for j, chk := range gcpChecks {
		if ps := granted[j]; len(ps) > 0 {
			f.Add(chk.sev, chk.what+" "+gcpWhere(ps), ps...)
		}
	}
	if len(getOnly) > 0 {
		f.Add(finding.Low, "see "+gcpWhere(getOnly), getOnly...)
	}
	if failed > 0 {
		f.Status = finding.Partial
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, Inferred: true,
			What: "use " + plural(failed, "more Google Cloud project", "more Google Cloud projects") + " that could not be checked"})
	}
	if checked == 0 && failed == 0 {
		f.Status = finding.Partial
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, Inferred: true,
			What: "use Google Cloud as " + f.Identity + "; no project could be checked"})
	}
	// Project checks cannot see IAM set on a single bucket, secret or
	// service account, so without a project-level grant keep the upper bound.
	// It stays at High like an unchecked credential; Critical here would
	// rate every Google credential Critical and drown the real ones.
	if f.Severity() < finding.High {
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, Inferred: true,
			What: "may hold grants on individual buckets, secrets or service accounts, which project-level checks cannot see"})
	}
	return f
}

const maxGCPProjectPages = 5

// listGCPProjects reports complete=false when a later page failed or the
// page cap was hit, so a long list is never mistaken for the whole one.
func listGCPProjects(ctx context.Context, o Options, auth map[string]string) ([]string, bool, int, error) {
	var ids []string
	token := ""
	for range maxGCPProjectPages {
		var page struct {
			Projects []struct {
				ProjectID string `json:"projectId"`
			} `json:"projects"`
			NextPageToken string `json:"nextPageToken"`
		}
		u := o.GoogleCRM + "/v1/projects?pageSize=200&filter=lifecycleState%3AACTIVE"
		if token != "" {
			u += "&pageToken=" + url.QueryEscape(token)
		}
		_, code, err := getJSON(ctx, o.HTTP, u, auth, &page)
		if err != nil || code/100 != 2 {
			if len(ids) > 0 {
				sort.Strings(ids)
				return ids, false, http.StatusOK, nil
			}
			return nil, false, code, err
		}
		for _, p := range page.Projects {
			ids = append(ids, p.ProjectID)
		}
		if token = page.NextPageToken; token == "" {
			sort.Strings(ids)
			return ids, true, http.StatusOK, nil
		}
	}
	sort.Strings(ids)
	return ids, false, http.StatusOK, nil
}

func gcpWhere(projects []string) string {
	w := plural(len(projects), "Google Cloud project", "Google Cloud projects")
	if looksProd(projects...) {
		w += ", some look like production"
	}
	return w
}

func gcpGuess(f finding.Finding) finding.Finding {
	c := f.Credential
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
	f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, What: what + "; roles not checked", Inferred: true})
	return f
}

// testIamPermissions is a read: it reports which of the listed permissions
// the caller holds and changes nothing.
func testGCPPermissions(ctx context.Context, o Options, auth map[string]string, project string) (map[string]bool, int, error) {
	perms := []string{"resourcemanager.projects.get"}
	for _, chk := range gcpChecks {
		perms = append(perms, chk.perms...)
	}
	body, _ := json.Marshal(map[string][]string{"permissions": perms})
	var out struct {
		Permissions []string `json:"permissions"`
	}
	code, err := postGoogle(ctx, o, o.GoogleCRM+"/v1/projects/"+url.PathEscape(project)+":testIamPermissions", "application/json", body, auth, &out)
	if err != nil || code/100 != 2 {
		return nil, code, err
	}
	have := map[string]bool{}
	for _, p := range out.Permissions {
		have[p] = true
	}
	return have, code, nil
}

var errGoogleRejected = errors.New("rejected by Google")

// googleUnchecked: the credential may well be live, we just could not ask.
type googleUnchecked struct{ why string }

func (e *googleUnchecked) Error() string { return e.why }

// googleToken always posts to Google's token endpoint: token_uri in the file
// is ignored, or a planted key file could send its signed assertion elsewhere.
func googleToken(ctx context.Context, o Options, k googleKey) (string, error) {
	form := url.Values{}
	if k.Type == "authorized_user" {
		form.Set("grant_type", "refresh_token")
		form.Set("client_id", k.ClientID)
		form.Set("client_secret", k.ClientSecret)
		form.Set("refresh_token", k.RefreshToken)
	} else {
		assertion, err := googleAssertion(k)
		if err != nil {
			return "", &googleUnchecked{"could not read the service account private key"}
		}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		form.Set("assertion", assertion)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	code, err := postGoogle(ctx, o, o.GoogleOAuth+"/token", "application/x-www-form-urlencoded", []byte(form.Encode()), nil, &out)
	if err != nil {
		return "", err
	}
	switch {
	case code/100 == 2 && out.AccessToken != "":
		return out.AccessToken, nil
	// A skewed laptop clock also gets invalid_grant; the key is still live.
	case out.Error == "invalid_grant" && strings.Contains(out.Description, "timeframe"):
		return "", &googleUnchecked{"Google refused the signed request; check this machine's clock"}
	case out.Error == "invalid_grant" || out.Error == "unauthorized_client":
		return "", errGoogleRejected
	case code/100 == 4:
		return "", &googleUnchecked{fmt.Sprintf("token endpoint returned HTTP %d", code)}
	}
	return "", fmt.Errorf("token endpoint returned HTTP %d", code)
}

func googleAssertion(k googleKey) (string, error) {
	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return "", errors.New("no PEM key")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, _ = parsed.(*rsa.PrivateKey)
	} else if k1, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k1
	}
	if key == nil {
		return "", errors.New("not an RSA key")
	}
	// Back-date a minute so a slightly fast clock is not refused.
	now := time.Now().Add(-time.Minute)
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": k.PrivateKeyID}) + "." + enc(map[string]any{
		"iss":   k.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   "https://oauth2.googleapis.com/token",
		"iat":   now.Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
	})
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// googleEmail posts the token in the body, never the URL, so a transport
// error cannot carry it into the report.
func googleEmail(ctx context.Context, o Options, token string) string {
	var out struct {
		Email string `json:"email"`
	}
	form := url.Values{"access_token": {token}}
	if code, err := postGoogle(ctx, o, o.GoogleOAuth+"/tokeninfo", "application/x-www-form-urlencoded", []byte(form.Encode()), nil, &out); err != nil || code/100 != 2 {
		return ""
	}
	return out.Email
}

func postGoogle(ctx context.Context, o Options, u, contentType string, body []byte, headers map[string]string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "howbad")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// A 307/308 would replay the body, refresh token included, to the new host.
	client := *o.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil {
		// OAuth errors come back as JSON on a 400, so decode those too.
		if err := json.Unmarshal(data, out); err != nil && resp.StatusCode/100 == 2 {
			return resp.StatusCode, fmt.Errorf("decoding %s: %w", req.URL.Path, err)
		}
	}
	return resp.StatusCode, nil
}
