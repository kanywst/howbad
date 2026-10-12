package resolve

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

type kubeCheck struct {
	verb, group, resource, sub string
	sev                        finding.Severity
	what                       string
	clusterScoped              bool
}

var kubeChecks = []kubeCheck{
	{"create", "rbac.authorization.k8s.io", "clusterrolebindings", "", finding.Critical, "grant itself cluster-admin (create clusterrolebindings)", true},
	{"get", "", "secrets", "", finding.Critical, "read Secrets", false},
	{"create", "", "pods", "exec", finding.High, "exec into pods", false},
	{"create", "", "pods", "", finding.High, "start arbitrary pods", false},
	{"patch", "apps", "deployments", "", finding.High, "change running deployments", false},
	{"delete", "", "namespaces", "", finding.High, "delete namespaces", true},
}

func kube(ctx context.Context, c cred.Credential, o Options) finding.Finding {
	f := finding.Finding{Credential: c}
	if o.NoExec && c.Ref["exec"] != "" {
		f.Status, f.Detail = finding.Skipped, "uses exec plugin "+c.Ref["exec"]+" (skipped by --no-exec)"
		return skippedGuess(f)
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: c.Ref["kubeconfig"]},
		&clientcmd.ConfigOverrides{CurrentContext: c.Ref["context"]},
	)
	rc, err := cc.ClientConfig()
	if err != nil {
		f.Status, f.Detail = finding.Invalid, cred.RedactURLs(err.Error())
		return f
	}
	if o.NoExec && (rc.ExecProvider != nil || rc.AuthProvider != nil) {
		f.Status, f.Detail = finding.Skipped, "uses a credential plugin (skipped by --no-exec)"
		return skippedGuess(f)
	}
	rc.Timeout = 8 * time.Second
	if rc.ExecProvider != nil {
		rc.ExecProvider.InteractiveMode = clientcmdapi.NeverExecInteractiveMode
		rc.ExecProvider.StdinUnavailable = true
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		f.Status, f.Detail = finding.Error, "could not build a client for this context"
		return f
	}
	cluster := c.Ref["cluster"]
	if u, err := url.Parse(c.Ref["server"]); err == nil && u.Host != "" {
		cluster = u.Host
	}
	where := "cluster " + cluster
	if looksProd(c.Ref["context"], cluster) {
		where += ", looks like production"
	}

	can := func(ns, verb, group, resource, sub string) (bool, error) {
		r, err := cs.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authzv1.SelfSubjectAccessReview{
			Spec: authzv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: ns, Verb: verb, Group: group, Resource: resource, Subresource: sub,
			}},
		}, metav1.CreateOptions{})
		if err != nil {
			return false, err
		}
		return r.Status.Allowed, nil
	}

	admin, err := can("", "*", "*", "*", "")
	if err != nil {
		var status apierrors.APIStatus
		switch {
		case !errors.As(err, &status) && strings.Contains(err.Error(), "getting credentials"):
			f.Status, f.Detail = finding.Expired, "credential plugin failed (expired login or missing binary)"
		case apierrors.IsUnauthorized(err):
			f.Status, f.Detail = finding.Invalid, "cluster rejected the credentials"
		case apierrors.IsForbidden(err):
			f.Status, f.Detail = finding.OK, "not allowed to ask what it can do"
			f.Identity = c.Ref["context"] + " @ " + cluster
			f.Add(finding.Low, "talk to the API of "+where)
		default:
			f.Status, f.Detail = finding.Unreachable, "cluster not reachable"
		}
		return f
	}
	f.Status = finding.OK
	f.Identity = c.Ref["context"] + " @ " + cluster
	if r, err := cs.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{}); err == nil && r.Status.UserInfo.Username != "" {
		f.Identity = r.Status.UserInfo.Username + " @ " + cluster
	}
	if admin {
		f.Add(finding.Critical, "do anything in "+where+" (cluster-admin)")
		return f
	}
	// Most people are bound per namespace, so a "no" cluster-wide is
	// re-asked in the context's namespace.
	ns := c.Ref["namespace"]
	if ns == "" {
		ns = "default"
	}
	failed := 0
	for _, ch := range kubeChecks {
		ok, err := can("", ch.verb, ch.group, ch.resource, ch.sub)
		scope := " in every namespace of " + where
		if ch.clusterScoped {
			scope = " in " + where
		}
		if err == nil && !ok && !ch.clusterScoped {
			ok, err = can(ns, ch.verb, ch.group, ch.resource, ch.sub)
			scope = " in namespace " + ns + " of " + where
		}
		if err != nil {
			failed++
			continue
		}
		if ok {
			f.Add(ch.sev, ch.what+scope)
		}
	}
	switch {
	case failed > 0:
		f.Status, f.Detail = finding.Partial, plural(failed, "permission check", "permission checks")+" failed"
	case len(f.Reach) == 0:
		f.Add(finding.Low, "no high-risk verbs in namespace "+ns+" of "+where)
	}
	return f
}
