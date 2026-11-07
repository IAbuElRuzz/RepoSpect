package findings

// Evidence describes a static observation, never proof of runtime execution.
type Evidence struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	EndLine     int    `json:"end_line"`
	EndColumn   int    `json:"end_column"`
	Kind        string `json:"kind"`
	Provenance  string `json:"provenance,omitempty"`
	Description string `json:"description"`
}
type Finding struct {
	ID          string     `json:"id"`
	Fingerprint string     `json:"fingerprint"`
	Limitations []string   `json:"limitations,omitempty"`
	RuleID      string     `json:"rule_id"`
	Severity    string     `json:"severity"`
	Confidence  string     `json:"confidence"`
	Category    string     `json:"category"`
	Description string     `json:"description"`
	Evidence    []Evidence `json:"evidence"`
	Impact      string     `json:"impact"`
	Remediation string     `json:"remediation"`
	Source      string     `json:"source"`
}
type Node struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}
type Edge struct {
	From         string   `json:"from"`
	To           string   `json:"to"`
	Kind         string   `json:"kind"`
	Relationship string   `json:"relationship"`
	Evidence     Evidence `json:"evidence"`
}
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}
type Component struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}
type Report struct {
	SchemaVersion string           `json:"schema_version"`
	Findings      []Finding        `json:"findings"`
	Graph         Graph            `json:"graph"`
	Components    []Component      `json:"components"`
	Modules       []ModuleCoverage `json:"modules"`
	Suppressions  []Suppression    `json:"suppressions,omitempty"`
	Coverage      []string         `json:"coverage"`
	Limitations   []string         `json:"limitations"`
	Files         int              `json:"files"`
	Bytes         int64            `json:"bytes"`
	Risk          int              `json:"risk_score"`
	Complete      bool             `json:"complete"`
}

func Rank(s string) int {
	switch s {
	case "INFO":
		return 0
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	}
	return -1
}
