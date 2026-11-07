package findings

import "testing"

func TestBoundedCoverageIssues(t *testing.T) {
	r := Report{Complete: true}
	for i := 0; i < 1000; i++ {
		r.Issue("parser", "partial", "limit", "fixture", "Input skipped")
	}
	m := r.Module("parser")
	if r.Complete || m.IssueCount != 1000 || len(m.Issues) != 64 {
		t.Fatalf("coverage not bounded: %+v", m)
	}
}
func TestSkippedOptionalModule(t *testing.T) {
	r := Report{Complete: true}
	m := r.Module("osv")
	m.Status = "skipped"
	m.Required = false
	r.Normalize()
	if !r.Complete {
		t.Fatal("optional skipped module reduced coverage")
	}
}
