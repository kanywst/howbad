package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/finding"
)

func aws(ctx context.Context, c cred.Credential, o Options) finding.Finding {
	f := finding.Finding{Credential: c}
	if o.NoExec && (c.Ref["exec"] != "" || c.Ref["auth"] == "credential_process" || sdkRunsProcess(ctx, c.Ref["profile"])) {
		return awsGuess(finding.Finding{Credential: c, Status: finding.Skipped, Detail: "runs credential_process (skipped by --no-exec)"})
	}
	var opts []func(*config.LoadOptions) error
	if id, secret, session, ok := c.AWSStatic(); ok {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(id, secret, session)))
	} else {
		opts = append(opts, config.WithSharedConfigProfile(c.Ref["profile"]))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		f.Status, f.Detail = finding.Error, "could not load this profile"
		return f
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	id, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		f.Status, f.Detail = awsCredError(err, c.Ref["auth"])
		if f.Status == finding.Expired {
			if cap, ok := inferFromRole(c.Ref["role"]); ok {
				cap.What += " once logged in again"
				f.Reach = append(f.Reach, cap)
			}
		}
		return f
	}
	arn := awssdk.ToString(id.Arn)
	account := awssdk.ToString(id.Account)
	f.Status, f.Identity = finding.OK, arn

	client := iam.NewFromConfig(cfg)
	label := account
	if al, err := client.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{}); err == nil && len(al.AccountAliases) > 0 {
		label = al.AccountAliases[0] + " (" + account + ")"
	}
	where := "AWS account " + label
	if looksProd(label, c.Ref["profile"]) {
		where += ", looks like production"
	}

	kind, name := parseARN(arn)
	if kind == "root" {
		f.Add(finding.Critical, "do anything as the root user of "+where)
		return f
	}
	policies, inlineAdmin, partial, err := awsPolicies(ctx, client, kind, name)
	if err != nil {
		// Most roles cannot read their own policies; fall back to the name.
		if cap, ok := inferFromRole(name); ok {
			cap.What += " in " + where
			f.Reach = append(f.Reach, cap)
		} else {
			f.Add(finding.Medium, "act as "+name+" in "+where+" (permissions not readable)")
		}
		return f
	}
	for _, cap := range classifyPolicies(policies, inlineAdmin) {
		cap.What += " in " + where
		f.Reach = append(f.Reach, cap)
	}
	if partial {
		f.Status, f.Detail = finding.Partial, "some IAM policy lookups failed"
	}
	if len(f.Reach) == 0 {
		f.Add(finding.Medium, fmt.Sprintf("act as %s in %s (%s attached)", name, where, plural(len(policies), "policy", "policies")))
	}
	return f
}

// sdkRunsProcess asks the SDK's own parser, so a quirk in howbad's INI
// reader cannot let --no-exec run a credential_process.
func sdkRunsProcess(ctx context.Context, profile string) bool {
	if profile == "" {
		return false
	}
	opts := func(o *config.LoadSharedConfigOptions) {
		if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
			o.ConfigFiles = []string{p}
		}
		if p := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); p != "" {
			o.CredentialsFiles = []string{p}
		}
	}
	sc, err := config.LoadSharedConfigProfile(ctx, profile, opts)
	if err != nil {
		return true
	}
	for p, depth := &sc, 0; p != nil; p, depth = p.Source, depth+1 {
		if p.CredentialProcess != "" || depth > 32 {
			return true
		}
	}
	return false
}

func awsOffline(c cred.Credential) finding.Finding {
	return awsGuess(finding.Finding{Credential: c, Status: finding.Skipped, Detail: "not checked (--offline)"})
}

func awsGuess(f finding.Finding) finding.Finding {
	if cap, ok := inferFromRole(f.Credential.Ref["role"]); ok {
		f.Reach = append(f.Reach, cap)
	} else {
		f.Reach = append(f.Reach, finding.Capability{Severity: finding.High, What: "use an AWS profile (permissions not checked)", Inferred: true})
	}
	return f
}

// Fixed messages only: provider errors can quote credential_process stdout.
func awsCredError(err error, auth string) (finding.Status, string) {
	// Not net.Error: syscall.Errno satisfies it, so a missing SSO cache
	// file would read as a network failure.
	var opErr *net.OpError
	var dnsErr *net.DNSError
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &opErr) || errors.As(err, &dnsErr) {
		return finding.Unreachable, "AWS not reachable"
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "ExpiredToken", "ExpiredTokenException", "RequestExpired":
			return finding.Expired, "session expired"
		case "InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException":
			return finding.Invalid, "AWS rejected the credentials (" + api.ErrorCode() + ")"
		}
	}
	var ssoErr *ssocreds.InvalidTokenError
	l := strings.ToLower(err.Error())
	if auth == "sso" && (errors.As(err, &ssoErr) || strings.Contains(l, "token has expired") ||
		strings.Contains(l, "sso session has expired") || strings.Contains(l, "cached sso token")) {
		return finding.Expired, "SSO session expired; one `aws sso login` away from working"
	}
	if api != nil {
		return finding.Error, "AWS returned " + api.ErrorCode()
	}
	return finding.Error, "could not get credentials for this profile"
}

func parseARN(arn string) (string, string) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "", ""
	}
	res := parts[5]
	switch {
	case res == "root":
		return "root", ""
	case strings.HasPrefix(res, "assumed-role/"):
		seg := strings.Split(res, "/")
		return "role", seg[1]
	case strings.HasPrefix(res, "user/"):
		return "user", res[strings.LastIndex(res, "/")+1:]
	case strings.HasPrefix(res, "role/"):
		return "role", res[strings.LastIndex(res, "/")+1:]
	}
	return "", res
}

// awsPolicies returns attached policy names, whether any inline policy
// allows * on *, and whether some lookups failed (so the result is a floor).
func awsPolicies(ctx context.Context, client *iam.Client, kind, name string) ([]string, bool, bool, error) {
	var names []string
	star, partial := false, false
	inline := func(list []string, err error, get func(string) (*string, error)) {
		if err != nil {
			partial = true
			return
		}
		for _, pn := range list {
			names = append(names, pn)
			doc, err := get(pn)
			if err != nil {
				partial = true
				continue
			}
			if grantsStar(awssdk.ToString(doc)) {
				star = true
			}
		}
	}
	switch kind {
	case "role":
		att, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: &name})
		if err != nil {
			return nil, false, false, err
		}
		for _, p := range att.AttachedPolicies {
			names = append(names, awssdk.ToString(p.PolicyName))
		}
		inl, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: &name})
		inline(policyNames(inl, err), err, func(pn string) (*string, error) {
			d, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: &name, PolicyName: &pn})
			if err != nil {
				return nil, err
			}
			return d.PolicyDocument, nil
		})
	case "user":
		att, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: &name})
		if err != nil {
			return nil, false, false, err
		}
		for _, p := range att.AttachedPolicies {
			names = append(names, awssdk.ToString(p.PolicyName))
		}
		inl, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: &name})
		inline(userPolicyNames(inl, err), err, func(pn string) (*string, error) {
			d, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: &name, PolicyName: &pn})
			if err != nil {
				return nil, err
			}
			return d.PolicyDocument, nil
		})
		groups, err := client.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: &name})
		if err != nil {
			partial = true
			break
		}
		for _, g := range groups.Groups {
			gn := g.GroupName
			ga, err := client.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: gn})
			if err != nil {
				partial = true
			} else {
				for _, p := range ga.AttachedPolicies {
					names = append(names, awssdk.ToString(p.PolicyName))
				}
			}
			gi, err := client.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{GroupName: gn})
			var gl []string
			if err == nil {
				gl = gi.PolicyNames
			}
			inline(gl, err, func(pn string) (*string, error) {
				d, err := client.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{GroupName: gn, PolicyName: &pn})
				if err != nil {
					return nil, err
				}
				return d.PolicyDocument, nil
			})
		}
	default:
		return nil, false, false, fmt.Errorf("unsupported principal type")
	}
	return names, star, partial, nil
}

func policyNames(o *iam.ListRolePoliciesOutput, err error) []string {
	if err != nil {
		return nil
	}
	return o.PolicyNames
}

func userPolicyNames(o *iam.ListUserPoliciesOutput, err error) []string {
	if err != nil {
		return nil
	}
	return o.PolicyNames
}

func grantsStar(encoded string) bool {
	raw, err := url.QueryUnescape(encoded)
	if err != nil {
		raw = encoded
	}
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return false
	}
	type stmt struct {
		Effect   string `json:"Effect"`
		Action   any    `json:"Action"`
		Resource any    `json:"Resource"`
	}
	var stmts []stmt
	if json.Unmarshal(doc.Statement, &stmts) != nil {
		var one stmt
		if json.Unmarshal(doc.Statement, &one) != nil {
			return false
		}
		stmts = []stmt{one}
	}
	for _, s := range stmts {
		if s.Effect == "Allow" && hasStar(s.Action) && hasStar(s.Resource) {
			return true
		}
	}
	return false
}

func hasStar(v any) bool {
	switch t := v.(type) {
	case string:
		return t == "*"
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}

func classifyPolicies(names []string, inlineAdmin bool) []finding.Capability {
	var full []string
	var out []finding.Capability
	readAll := false
	for _, n := range names {
		switch {
		case n == "AdministratorAccess":
			return []finding.Capability{{Severity: finding.Critical, What: "do anything (AdministratorAccess)"}}
		case n == "PowerUserAccess":
			out = append(out, finding.Capability{Severity: finding.Critical, What: "do anything except manage IAM (PowerUserAccess)"})
		case n == "ReadOnlyAccess" || n == "ViewOnlyAccess":
			readAll = true
		case strings.HasSuffix(n, "FullAccess"):
			full = append(full, strings.TrimSuffix(strings.TrimPrefix(n, "Amazon"), "FullAccess"))
		}
	}
	if inlineAdmin {
		return []finding.Capability{{Severity: finding.Critical, What: "do anything (inline policy allows * on *)"}}
	}
	if len(full) > 0 {
		out = append(out, finding.Capability{Severity: finding.High, What: "fully control " + strings.Join(full, ", ")})
	}
	if readAll {
		out = append(out, finding.Capability{Severity: finding.High, What: "read everything, including S3 objects and Secrets Manager metadata (ReadOnlyAccess)"})
	}
	return out
}

// SSO roles are named AWSReservedSSO_<PermissionSet>_<hash>.
func inferFromRole(role string) (finding.Capability, bool) {
	if role == "" {
		return finding.Capability{}, false
	}
	name := role
	if strings.HasPrefix(name, "AWSReservedSSO_") {
		name = strings.TrimPrefix(name, "AWSReservedSSO_")
		if i := strings.LastIndex(name, "_"); i > 0 {
			name = name[:i]
		}
	}
	l := strings.ToLower(name)
	c := finding.Capability{Inferred: true}
	switch {
	case strings.Contains(l, "admin"):
		c.Severity, c.What = finding.Critical, "likely do anything (role "+name+")"
	case strings.Contains(l, "poweruser"):
		c.Severity, c.What = finding.Critical, "likely do anything except IAM (role "+name+")"
	case strings.Contains(l, "readonly") || strings.Contains(l, "viewonly"):
		c.Severity, c.What = finding.High, "likely read everything (role "+name+")"
	default:
		c.Severity, c.What = finding.Medium, "act as role "+name+" (permissions unknown)"
	}
	return c, true
}
