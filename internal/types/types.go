package types

import (
	"github.com/pkg/browser"
	"github.com/rs/zerolog/log"
)

type FilePath string

type OpenBrowserFunc func(url string)

var (
	DefaultOpenBrowserFunc OpenBrowserFunc = func(url string) {
		browser.Stdout = log.Logger
		_ = browser.OpenURL(url)
	}
)

type DataflowElement struct {
	Position  int      `json:"position"`
	FilePath  FilePath `json:"filePath"`
	FlowRange Range    `json:"flowRange"`
	Content   string   `json:"content"`
}

type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// IssueData contains extracted issue information for serialization
type IssueData struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Severity    string            `json:"severity"`
	Dataflow    []DataflowElement `json:"dataflow,omitempty"`
	CWEs        []string          `json:"cwes,omitempty"`
	CVEs        []string          `json:"cves,omitempty"`
	PackageName string            `json:"packageName,omitempty"`
	Version     string            `json:"version,omitempty"`
	Ecosystem   string            `json:"ecosystem,omitempty"`
	FixedIn     []string          `json:"fixedIn,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	FilePath    string            `json:"filePath,omitempty"`
	Line        int               `json:"line,omitempty"`
	Column      int               `json:"column,omitempty"`
	Message     string            `json:"message,omitempty"`
	FingerPrint string            `json:"fingerPrint,omitempty"`
	IsIgnored   bool              `json:"isIgnored,omitempty"`
}

var IssuesSeverity = map[string]Severity{
	"critical": Critical,
	"high":     High,
	"low":      Low,
	"medium":   Medium,
}

type Severity int8

const (
	Critical Severity = iota
	High
	Medium
	Low
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "Critical"
	case High:
		return "High"
	case Medium:
		return "Medium"
	case Low:
		return "Low"
	default:
		return "unknown"
	}
}
