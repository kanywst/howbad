package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kanywst/howbad/internal/cred"
	"github.com/kanywst/howbad/internal/discover"
	"github.com/kanywst/howbad/internal/finding"
	"github.com/kanywst/howbad/internal/report"
	"github.com/kanywst/howbad/internal/resolve"
)

var version = "dev"

var errThreshold = errors.New("severity threshold reached")

type flags struct {
	offline bool
	noExec  bool
	json    bool
	verbose bool
	failOn  string
	only    []string
	timeout time.Duration
}

func Execute() int {
	root := NewRootCmd(defaultEnv(), resolve.Options{})
	if err := root.Execute(); err != nil {
		if errors.Is(err, errThreshold) {
			return 2
		}
		fmt.Fprintln(os.Stderr, "howbad:", err)
		return 1
	}
	return 0
}

func defaultEnv() discover.Env {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	vars := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			vars[k] = v
		}
	}
	return discover.Env{Home: home, Cwd: cwd, Vars: vars, GOOS: runtime.GOOS, Exec: runHelper, ClaudeManaged: discover.ClaudeManagedDir(runtime.GOOS)}
}

func runHelper(ctx context.Context, name string, args ...string) (string, error) {
	timeout := 5 * time.Second
	if name == "gcloud" {
		// Python start-up plus a token refresh.
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	// Otherwise gh auth token echoes $GH_TOKEN, not the keychain token.
	for _, kv := range os.Environ() {
		switch k, _, _ := strings.Cut(kv, "="); k {
		case "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN":
		default:
			cmd.Env = append(cmd.Env, kv)
		}
	}
	out, err := cmd.Output()
	return string(out), err
}

func NewRootCmd(env discover.Env, ropts resolve.Options) *cobra.Command {
	var fl flags
	cmd := &cobra.Command{
		Use:   "howbad",
		Short: "If a coding agent on this machine got hijacked right now, how bad would it be?",
		Long: `howbad finds every credential a coding agent running as you could pick up
(shell env, gh, npm, AWS, kubeconfig, gcloud, and tokens pasted into the
configs of Claude Code, Codex, Cursor, Gemini CLI, VS Code, Windsurf, Devin
Desktop and Claude Desktop) and asks each provider, read-only, what that
credential can actually do.

Nothing is sent anywhere except the provider that issued each credential,
and secrets are never printed.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return run(c.Context(), c.OutOrStdout(), c.ErrOrStderr(), env, ropts, fl)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&fl.offline, "offline", false, "find credentials but make no network calls")
	f.BoolVar(&fl.noExec, "no-exec", false, "do not run credential helpers (gh auth token, gcloud auth print-access-token, credential_process, kubeconfig exec plugins)")
	f.BoolVar(&fl.json, "json", false, "print JSON instead of the report")
	f.BoolVarP(&fl.verbose, "verbose", "v", false, "show low-severity reach and every credential that could not be checked")
	f.StringVar(&fl.failOn, "fail-on", "", "exit 2 if anything reachable is at or above this severity (info|low|medium|high|critical)")
	f.StringSliceVar(&fl.only, "only", nil, "only check these kinds (github,npm,slack,aws,kubernetes,gcp,...)")
	f.DurationVar(&fl.timeout, "timeout", 20*time.Second, "time limit per credential")
	return cmd
}

func run(ctx context.Context, w, errw io.Writer, env discover.Env, ropts resolve.Options, fl flags) error {
	var threshold finding.Severity
	if fl.failOn != "" {
		s, err := finding.ParseSeverity(fl.failOn)
		if err != nil {
			return err
		}
		threshold = s
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if fl.noExec {
		env.Exec = nil
	}
	env.Offline = fl.offline

	found := discover.Run(ctx, env)
	creds := found.Credentials
	if len(fl.only) > 0 {
		keep := map[string]bool{}
		for _, k := range fl.only {
			k = strings.ToLower(strings.TrimSpace(k))
			if !cred.Known(k) {
				return fmt.Errorf("--only: unknown kind %q (want one of %s)", k, strings.Join(cred.KindNames(), ", "))
			}
			keep[k] = true
		}
		filtered := creds[:0]
		for _, c := range creds {
			if keep[string(c.Kind)] {
				filtered = append(filtered, c)
			}
		}
		creds = filtered
	}

	ropts.Offline, ropts.NoExec, ropts.Timeout = fl.offline, fl.noExec, fl.timeout
	findings := report.Dedupe(resolve.All(ctx, creds, ropts))
	r := report.Report{Version: version, Found: len(creds), Agents: found.Agents, Findings: findings}

	if fl.json {
		if err := report.JSON(w, r); err != nil {
			return err
		}
	} else {
		report.Text(w, r, fl.verbose)
	}
	if threshold != finding.None {
		if report.Highest(findings) >= threshold {
			return errThreshold
		}
		if n := report.Unreachable(findings); n > 0 {
			fmt.Fprintf(errw, "howbad: %d credential(s) could not be checked; --fail-on cannot vouch for them\n", n)
			return errThreshold
		}
	}
	return nil
}
