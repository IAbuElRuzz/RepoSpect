# Contributing

Keep scans deterministic, bounded, local by default, and free of untrusted execution. Add table-driven regression cases for new detections, including benign examples. Evidence must support the actual claim; never equate a static indicator with confirmed compromise. Do not add real secrets, live attack infrastructure or functional malware to fixtures.

Run gofmt, go test ./..., go test -race ./... and go vet ./... before proposing changes. Document unsupported input and any network behavior. No external scanner failure may become a clean report. Discuss changes to the threat model and privacy behavior before implementation. Contributions are under Apache-2.0.
