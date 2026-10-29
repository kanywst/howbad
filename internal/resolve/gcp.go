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
		if errors.Is(err, errGoogleRejected) {
			f.Status, f.Detail = finding.Expired, "Google rejected it (revoked or expired; log in again)"
			return f
		}
		if err != nil {
			return gcpGuess(netFailure(f, err))
		}
	default:
		// external_account can run a program and impersonation chains go
		// through other credentials; neither is exchanged here.
		f.Status, f.Detail = finding.Unverified, fmt.Sprintf("credential type %q is not checked", key.Type)
		return gcpGuess(f)
	}

	auth := map[string]string{"Authorization": "Bearer " + token}
	f.Identity = key.ClientEmail
	if f.Identity == "" {
		f.Identity = c.Ref["account"]
	}
	if f.Identity == "" {
		f.Identity = googleEmail(ctx, o, token)
	}

	var listed struct {
		Projects []struct {
			ProjectID string `json:"projectId"`
		} `json:"projects"`
	}
	_, code, err := getJSON(ctx, o.HTTP, o.GoogleCRM+"/v1/projects?pageSize=200&filter=lifecycleState%3AACTIVE", auth, &listed)
	if err != nil {
		return gcpGuess(netFailure(f, err))
	}
	if code == http.StatusUnauthorized {
		f.Status, f.Detail = finding.Expired, "Google rejected the token (expired; log in again)"
		return f
	}
	var projects []string
	seen := map[string]bool{}
	for _, p := range append([]string{c.Ref["project"], key.ProjectID, key.QuotaProjectID}, projectIDs(listed.Projects)...) {
		if p != "" && !seen[p] {
			seen[p] = true
			projects = append(projects, p)
		}
	}
	f.Status = finding.OK
	if code/100 != 2 {
		f.Status, f.Detail = finding.Partial, fmt.Sprintf("could not list projects (HTTP %d)", code)
	}
	if len(projects) == 0 {
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, Inferred: true,
			What: "use Google Cloud as " + f.Identity + "; no project visible to check"})
		return f
	}

	granted := map[int][]string{}
	checked, getOnly := 0, []string{}
	for i, p := range projects {
		if i == maxGCPProjects {
			f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, Inferred: true,
				What: fmt.Sprintf("use %s not checked (only the first %d are)", plural(len(projects)-maxGCPProjects, "more Google Cloud project", "more Google Cloud projects"), maxGCPProjects)})
			break
		}
		have, err := testGCPPermissions(ctx, o, auth, p)
		if err != nil {
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
	if checked == 0 {
		f.Status, f.Detail = finding.Partial, "could not test permissions on any project"
		return gcpGuess(f)
	}
	for j, chk := range gcpChecks {
		if ps := granted[j]; len(ps) > 0 {
			f.Add(chk.sev, chk.what+" "+gcpWhere(ps), ps...)
		}
	}
	if len(getOnly) > 0 {
		f.Add(finding.Low, "see "+gcpWhere(getOnly), getOnly...)
	}
	return f
}

func gcpWhere(projects []string) string {
	w := plural(len(projects), "Google Cloud project", "Google Cloud projects")
	if looksProd(projects...) {
		w += ", some look like production"
	}
	return w
}

func projectIDs(ps []struct {
	ProjectID string `json:"projectId"`
}) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.ProjectID)
	}
	sort.Strings(out)
	return out
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
func testGCPPermissions(ctx context.Context, o Options, auth map[string]string, project string) (map[string]bool, error) {
	perms := []string{"resourcemanager.projects.get"}
	for _, chk := range gcpChecks {
		perms = append(perms, chk.perms...)
	}
	body, _ := json.Marshal(map[string][]string{"permissions": perms})
	var out struct {
		Permissions []string `json:"permissions"`
	}
	code, err := postGoogle(ctx, o, o.GoogleCRM+"/v1/projects/"+url.PathEscape(project)+":testIamPermissions", "application/json", body, auth, &out)
	if err != nil {
		return nil, err
	}
	if code/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", code)
	}
	have := map[string]bool{}
	for _, p := range out.Permissions {
		have[p] = true
	}
	return have, nil
}

var errGoogleRejected = errors.New("rejected by Google")

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
			return "", errGoogleRejected
		}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		form.Set("assertion", assertion)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	code, err := postGoogle(ctx, o, o.GoogleOAuth+"/token", "application/x-www-form-urlencoded", []byte(form.Encode()), nil, &out)
	if err != nil {
		return "", err
	}
	if code == http.StatusBadRequest || code == http.StatusUnauthorized || (code/100 == 2 && out.AccessToken == "") {
		return "", errGoogleRejected
	}
	if code/100 != 2 {
		return "", fmt.Errorf("token endpoint returned HTTP %d", code)
	}
	return out.AccessToken, nil
}

func googleAssertion(k googleKey) (string, error) {
	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return "", errors.New("no PEM key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("not an RSA key")
	}
	now := time.Now()
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
	if resp.StatusCode/100 == 2 && out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decoding %s: %w", req.URL.Path, err)
		}
	}
	return resp.StatusCode, nil
}
