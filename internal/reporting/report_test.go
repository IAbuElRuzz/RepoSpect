package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/IAbuElRuzz/RepoSpect/internal/scanner"
	"testing"
)

func TestFormats(t *testing.T) {
	r, err := (scanner.Engine{Options: scanner.Defaults()}).Scan(context.Background(), "../../testdata/suspicious")
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "sarif", "sbom", "text", "mermaid", "dot"} {
		t.Run(format, func(t *testing.T) {
			var b bytes.Buffer
			if err := Write(&b, r, format); err != nil {
				t.Fatal(err)
			}
			if b.Len() == 0 {
				t.Fatal("empty output")
			}
			if (format == "json" || format == "sarif" || format == "sbom") && !json.Valid(b.Bytes()) {
				t.Fatal("invalid JSON")
			}
		})
	}
}
