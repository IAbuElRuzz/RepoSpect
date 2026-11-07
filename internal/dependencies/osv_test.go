package dependencies

import (
	"context"
	f "github.com/IAbuElRuzz/RepoSpect/pkg/findings"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (fn transport) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }
func TestOSV(t *testing.T) {
	for _, tc := range []struct {
		body string
		bad  bool
	}{{`{"results":[{"vulns":[{"id":"GHSA-example-1234"}]}]}`, false}, {`{"results":[]}`, true}, {`{"results":[{"next_page_token":"more"}]}`, true}, {`invalid`, true}} {
		r := f.Report{Components: []f.Component{{Name: "example", Version: "1.2.3", Ecosystem: "npm"}}}
		c := Client{Endpoint: "https://osv.invalid", HTTP: &http.Client{Transport: transport(func(req *http.Request) (*http.Response, error) {
			if req.Method != "POST" {
				t.Fatal("expected POST")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}}
		err := c.Check(context.Background(), &r)
		if (err != nil) != tc.bad {
			t.Fatalf("%s: %v", tc.body, err)
		}
		if !tc.bad && (len(r.Findings) != 1 || r.Findings[0].Category != "vulnerability") {
			t.Fatal("missing vulnerability")
		}
	}
}

func TestOSVFailedCoverage(t *testing.T) {
	r := f.Report{Complete: true, Components: []f.Component{{Name: "demo", Version: "1.2.3", Ecosystem: "npm"}}}
	c := Client{Endpoint: "https://osv.invalid", HTTP: &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
	})}}
	if c.Check(context.Background(), &r) == nil {
		t.Fatal("expected failure")
	}
	if r.Complete || r.Module("osv").Status != "failed" || len(r.Findings) != 0 {
		t.Fatal("failure became clean coverage")
	}
}
