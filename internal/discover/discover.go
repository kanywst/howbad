package discover

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kanywst/howbad/internal/cred"
)

type Env struct {
	Home string
	Cwd  string
	Vars map[string]string
	GOOS string
	// ClaudeManaged is Claude Code's managed settings directory; empty
	// skips it, which keeps tests off the real machine's files.
	ClaudeManaged string
	// Exec runs credential helpers; nil means --no-exec.
	Exec func(ctx context.Context, name string, args ...string) (string, error)
	// Offline skips helpers that would reach the network themselves.
	Offline bool
}

type Agent struct {
	Name    string `json:"name"`
	Config  string `json:"config,omitempty"`
	Posture string `json:"posture,omitempty"`
}

type Result struct {
	Credentials []cred.Credential
	Agents      []Agent
}

func Run(ctx context.Context, env Env) Result {
	var all []cred.Credential
	all = append(all, fromEnv(env)...)
	all = append(all, fromGH(ctx, env)...)
	all = append(all, fromNPM(env)...)
	all = append(all, fromAWS(env)...)
	all = append(all, fromKube(env)...)
	all = append(all, fromGCP(ctx, env)...)
	agentCreds, agents := fromAgents(env)
	all = append(all, agentCreds...)
	return Result{Credentials: cred.Merge(all), Agents: agents}
}

func (e Env) tilde(p string) string {
	if e.Home != "" && strings.HasPrefix(p, e.Home+string(filepath.Separator)) {
		return "~" + p[len(e.Home):]
	}
	if e.Cwd != "" && strings.HasPrefix(p, e.Cwd+string(filepath.Separator)) {
		return "." + p[len(e.Cwd):]
	}
	return p
}

const maxConfigBytes = 4 << 20

// A repo can check in .mcp.json as a symlink to /dev/zero.
func readConfig(p string) ([]byte, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxConfigBytes {
		return nil, fmt.Errorf("%s: not a regular file under %d bytes", p, maxConfigBytes)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxConfigBytes))
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func parseINI(path string) (map[string]map[string]string, []string) {
	data, err := readConfig(path)
	if err != nil {
		return nil, nil
	}
	sections := map[string]map[string]string{}
	var order []string
	cur := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			cur = strings.TrimSpace(line[1:strings.Index(line, "]")])
			if _, ok := sections[cur]; !ok {
				sections[cur] = map[string]string{}
				order = append(order, cur)
			}
			continue
		}
		// Match the AWS SDK: either separator, case-insensitive keys.
		i := strings.IndexAny(line, "=:")
		if i < 0 || cur == "" {
			continue
		}
		sections[cur][strings.ToLower(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
	}
	return sections, order
}
