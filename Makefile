.PHONY: test fmt-check cli-test registry-test audit-agent-image

test: cli-test registry-test

cli-test:
	cd cli && cargo test

registry-test:
	cd registry && go test ./...

fmt-check:
	cd cli && cargo fmt --check
	cd registry && test -z "$$(gofmt -l .)"

audit-agent-image:
	cd registry && CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) go build -o ../audit-agent/registry-audit-agent ./cmd/audit-agent
	docker build -f audit-agent/Dockerfile.static -t rivet-audit-agent:local audit-agent
