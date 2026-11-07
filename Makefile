.PHONY: build test check clean
build:
	go build -trimpath -o bin/repospect ./cmd/repospect
test:
	go test ./...
check:
	go vet ./...
	go test -race ./...
clean:
	rm -rf bin dist
