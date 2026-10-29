package resolve

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

// gcpServer fakes the OAuth and Resource Manager endpoints. grants maps a
// project to the permissions testIamPermissions returns for it.
func gcpServer(t *testing.T, access string, grants map[string][]string, token http.HandlerFunc) Options {
	t.Helper()
	return server(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token" && token != nil:
			token(w, r)
		case r.URL.Path == "/tokeninfo":
			_ = r.ParseForm()
			if r.URL.RawQuery != "" || r.PostForm.Get("access_token") != access {
				w.WriteHeader(400)
				return
			}
			fmt.Fprint(w, `{"email":"me@example.com"}`)
		case !requireBearer(t, r, access):
			w.WriteHeader(401)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects":
			var ps []string
			for p := range grants {
				ps = append(ps, fmt.Sprintf(`{"projectId":%q}`, p))
			}
			fmt.Fprint(w, `{"projects":[`+strings.Join(ps, ",")+`]}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, ":testIamPermissions"):
			p := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/projects/"), ":testIamPermissions")
			have, ok := grants[p]
			if !ok {
				w.WriteHeader(403)
				return
			}
			var req struct{ Permissions []string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			asked := map[string]bool{}
			for _, x := range req.Permissions {
				asked[x] = true
			}
			var out []string
			for _, x := range have {
				if asked[x] {
					out = append(out, x)
				}
			}
			b, _ := json.Marshal(map[string][]string{"permissions": out})
			_, _ = w.Write(b)
		default:
			w.WriteHeader(404)
		}
	})
}

func gcloudCred(tok string) cred.Credential {
	c := cred.New(cred.GCP, "gcloud me@example.com", "~/.config/gcloud/configurations/config_default", tok)
	c.Ref = map[string]string{"account": "me@example.com", "project": "acme-prod"}
	return c
}

func TestGCPGcloudAccount(t *testing.T) {
	tok := "ya29." + strings.Repeat("g", 40)
	o := gcpServer(t, tok, map[string][]string{
		"acme-prod": {"resourcemanager.projects.get", "resourcemanager.projects.setIamPolicy", "secretmanager.versions.access"},
		"sandbox":   {"resourcemanager.projects.get"},
	}, nil)
	f := One(context.Background(), gcloudCred(tok), o)
	if f.Status != finding.OK || f.Identity != "me@example.com" || f.Severity() != finding.Critical {
		t.Fatalf("status %s identity %q severity %s detail %q", f.Status, f.Identity, f.Severity(), f.Detail)
	}
	if !hasWhat(f, "grant anyone any role (owner-level control) on 1 Google Cloud project, some look like production") ||
		!hasWhat(f, "read Secret Manager secrets in 1 Google Cloud project") || !hasWhat(f, "see 1 Google Cloud project") {
		t.Fatalf("reach: %+v", f.Reach)
	}
	if hasWhat(f, "act as service accounts") || f.Reach[0].Inferred {
		t.Fatalf("only granted permissions should be reported, and not as inferred: %+v", f.Reach)
	}
}

func TestGCPAuthorizedUserIgnoresTokenURI(t *testing.T) {
	access := "ya29." + strings.Repeat("a", 40)
	refresh := "1//" + strings.Repeat("r", 40)
	var hits atomic.Int32
	planted := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(planted.Close)
	o := gcpServer(t, access, map[string][]string{"dev": {"storage.objects.get"}}, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != refresh {
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `{"access_token":%q}`, access)
	})
	adc := fmt.Sprintf(`{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":%q,"token_uri":%q}`, refresh, planted.URL+"/token")
	c := cred.New(cred.GCP, "Google Application Default Credentials", "~/.config/gcloud/application_default_credentials.json", adc)
	c.Ref = map[string]string{"adc": "true", "type": "authorized_user"}
	f := One(context.Background(), c, o)
	if f.Status != finding.OK || f.Identity != "me@example.com" || !hasWhat(f, "read data (Cloud Storage, BigQuery, Cloud SQL) in 1 Google Cloud project") {
		t.Fatalf("%s %q %q %+v", f.Status, f.Identity, f.Detail, f.Reach)
	}
	if hits.Load() != 0 {
		t.Fatal("token_uri from the credential file was used")
	}
}

func TestGCPServiceAccountKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Older keys come as PKCS#1; both must sign.
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	access := "ya29." + strings.Repeat("s", 40)
	o := gcpServer(t, access, map[string][]string{"ci-proj": {"iam.serviceAccountKeys.create", "run.services.create"}}, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		parts := strings.Split(r.PostForm.Get("assertion"), ".")
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || len(parts) != 3 {
			w.WriteHeader(400)
			return
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
			w.WriteHeader(400)
			return
		}
		claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if !strings.Contains(string(claims), `"iss":"ci@ci-proj.iam.gserviceaccount.com"`) {
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `{"access_token":%q}`, access)
	})
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "ci@ci-proj.iam.gserviceaccount.com", "private_key": pemKey, "project_id": "ci-proj"})
	c := cred.New(cred.GCP, "$GOOGLE_APPLICATION_CREDENTIALS", "~/sa.json", string(sa))
	c.Ref = map[string]string{"keyfile": "true", "type": "service_account"}
	f := One(context.Background(), c, o)
	if f.Status != finding.OK || f.Identity != "ci@ci-proj.iam.gserviceaccount.com" || f.Severity() != finding.Critical ||
		!hasWhat(f, "act as service accounts (mint keys or tokens) in 1 Google Cloud project") || !hasWhat(f, "run code and spend money") {
		t.Fatalf("%s %q %q %+v", f.Status, f.Identity, f.Detail, f.Reach)
	}
}

func TestGCPRevokedRefreshToken(t *testing.T) {
	o := gcpServer(t, "unused", nil, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	})
	c := cred.New(cred.GCP, "adc", "x", `{"type":"authorized_user","refresh_token":"1//revoked"}`)
	c.Ref = map[string]string{"adc": "true"}
	if f := One(context.Background(), c, o); f.Status != finding.Expired {
		t.Fatalf("%s %q", f.Status, f.Detail)
	}
}

func TestGCPTokenEndpointRedirectNotFollowed(t *testing.T) {
	refresh := "1//" + strings.Repeat("x", 40)
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), refresh) {
			t.Error("refresh token was replayed to a redirect target")
		}
	}))
	t.Cleanup(other.Close)
	target := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+r.URL.Path, http.StatusTemporaryRedirect)
	})
	c := cred.New(cred.GCP, "adc", "x", `{"type":"authorized_user","refresh_token":"`+refresh+`"}`)
	c.Ref = map[string]string{"adc": "true"}
	f := One(context.Background(), c, o)
	if strings.Contains(f.Detail, refresh) || f.Severity() != finding.High || !f.Reach[0].Inferred {
		t.Fatalf("%s %q %+v", f.Status, f.Detail, f.Reach)
	}
}

func TestGCPWithoutTokenKeepsAGuess(t *testing.T) {
	o := server(t, func(_ http.ResponseWriter, r *http.Request) { t.Errorf("unexpected call: %s", r.URL) })
	ext := cred.New(cred.GCP, "adc", "x", `{"type":"external_account","credential_source":{"executable":{"command":"/bin/sh"}}}`)
	ext.Ref = map[string]string{"adc": "true"}
	noTok := cred.Credential{Kind: cred.GCP, Via: "gcloud me@example.com", Ref: map[string]string{"account": "me@example.com", "project": "p"}}
	for _, tc := range []struct {
		c      cred.Credential
		noExec bool
		want   finding.Status
	}{
		{ext, false, finding.Unverified},
		{noTok, true, finding.Skipped},
		{noTok, false, finding.Unverified},
	} {
		o.NoExec = tc.noExec
		f := One(context.Background(), tc.c, o)
		if f.Status != tc.want || f.Severity() != finding.High || !f.Reach[0].Inferred {
			t.Errorf("%s: %s %q %+v", tc.c.Via, f.Status, f.Detail, f.Reach)
		}
	}
	o.NoExec, o.Offline = false, true
	if f := One(context.Background(), gcloudCred("ya29.x"), o); f.Status != finding.Skipped || f.Severity() != finding.High {
		t.Fatalf("offline: %s %+v", f.Status, f.Reach)
	}
}

func TestGCPTooManyProjectsIsUpperBound(t *testing.T) {
	tok := "ya29." + strings.Repeat("m", 40)
	grants := map[string][]string{}
	for i := range maxGCPProjects + 3 {
		grants[fmt.Sprintf("p-%02d", i)] = []string{"resourcemanager.projects.get"}
	}
	f := One(context.Background(), gcloudCred(tok), gcpServer(t, tok, grants, nil))
	// acme-prod comes from gcloud config and is not in the list, so 29 in all.
	if !hasWhat(f, "use 4 more Google Cloud projects that could not be checked") || f.Severity() != finding.High {
		t.Fatalf("%+v", f.Reach)
	}
}

func TestGCPResourceLevelGrantsKeepUpperBound(t *testing.T) {
	tok := "ya29." + strings.Repeat("e", 40)
	f := One(context.Background(), gcloudCred(tok), gcpServer(t, tok, map[string][]string{"acme-prod": {}}, nil))
	if f.Status != finding.OK || f.Severity() != finding.High || !hasWhat(f, "individual buckets, secrets or service accounts") || !f.Reach[0].Inferred {
		t.Fatalf("%s %+v", f.Status, f.Reach)
	}
}

func TestGCPFailedProjectIsPartial(t *testing.T) {
	tok := "ya29." + strings.Repeat("f", 40)
	o := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/projects":
			fmt.Fprint(w, `{"projects":[{"projectId":"ok-proj"},{"projectId":"flaky"},{"projectId":"hidden"}]}`)
		case strings.Contains(r.URL.Path, "ok-proj"):
			fmt.Fprint(w, `{"permissions":["secretmanager.versions.access"]}`)
		case strings.Contains(r.URL.Path, "hidden"):
			w.WriteHeader(403)
		default:
			w.WriteHeader(503)
		}
	})
	c := gcloudCred(tok)
	c.Ref["project"] = ""
	f := One(context.Background(), c, o)
	if f.Status != finding.Partial || !hasWhat(f, "read Secret Manager secrets in 1") || !hasWhat(f, "use 1 more Google Cloud project that could not be checked") {
		t.Fatalf("%s %+v", f.Status, f.Reach)
	}
}

func TestGCPClockSkewIsNotExpired(t *testing.T) {
	o := gcpServer(t, "unused", nil, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Invalid JWT: Token must be a short-lived token (60 minutes) and in a reasonable timeframe."}`)
	})
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "ci@p.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	c := cred.New(cred.GCP, "key", "x", string(sa))
	f := One(context.Background(), c, o)
	if f.Status != finding.Unverified || !strings.Contains(f.Detail, "clock") || f.Severity() != finding.High {
		t.Fatalf("%s %q %+v", f.Status, f.Detail, f.Reach)
	}
	bad := cred.New(cred.GCP, "key", "x", `{"type":"service_account","private_key":"not a key"}`)
	if f := One(context.Background(), bad, o); f.Status != finding.Unverified || f.Severity() != finding.High {
		t.Fatalf("unreadable key: %s %q", f.Status, f.Detail)
	}
}

func TestGCPImpersonatedIdentity(t *testing.T) {
	tok := "ya29." + strings.Repeat("i", 40)
	c := gcloudCred(tok)
	c.Ref["impersonate"] = "deploy@p.iam.gserviceaccount.com"
	f := One(context.Background(), c, gcpServer(t, tok, map[string][]string{"acme-prod": {"resourcemanager.projects.setIamPolicy"}}, nil))
	if f.Identity != "deploy@p.iam.gserviceaccount.com" {
		t.Fatalf("identity %q", f.Identity)
	}
}
