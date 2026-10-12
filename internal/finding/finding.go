package finding

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kanywst/howbad/internal/cred"
)

type Severity int

const (
	None Severity = iota
	Info
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"none", "info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if int(s) < len(severityNames) {
		return severityNames[s]
	}
	return "unknown"
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func ParseSeverity(v string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(v, n) && i > 0 {
			return Severity(i), nil
		}
	}
	return None, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", v)
}

type Status string

const (
	OK          Status = "ok"
	Partial     Status = "partial"
	Invalid     Status = "invalid"
	Expired     Status = "expired"
	Unreachable Status = "unreachable"
	Unverified  Status = "unverified"
	Skipped     Status = "skipped"
	Error       Status = "error"
)

type Capability struct {
	Severity Severity `json:"severity"`
	What     string   `json:"what"`
	Examples []string `json:"examples,omitempty"`
	Inferred bool     `json:"inferred,omitempty"`
}

type Finding struct {
	Credential cred.Credential `json:"credential"`
	Identity   string          `json:"identity,omitempty"`
	Status     Status          `json:"status"`
	Detail     string          `json:"detail,omitempty"`
	Reach      []Capability    `json:"reach,omitempty"`
}

func (f Finding) Severity() Severity {
	max := None
	for _, c := range f.Reach {
		if c.Severity > max {
			max = c.Severity
		}
	}
	return max
}

func (f *Finding) Add(sev Severity, what string, examples ...string) {
	f.Reach = append(f.Reach, Capability{Severity: sev, What: what, Examples: examples})
}

func (f Finding) MarshalJSON() ([]byte, error) {
	type alias Finding
	return json.Marshal(struct {
		alias
		Severity Severity `json:"severity"`
	}{alias(f), f.Severity()})
}
