.PHONY: test fmt-check cli-test cli-clippy cli-fmt-check registry-test registry-fmt-check audit-agent-check audit-agent-image workspace-check workspace-sync docs-check schema-check examples-check fixtures-check

test: workspace-check cli-test registry-test

cli-test:
	cd cli && cargo test

cli-clippy:
	cd cli && cargo clippy --all-targets -- -D warnings

cli-fmt-check:
	cd cli && cargo fmt --check

registry-test:
	cd registry && go test ./...

registry-fmt-check:
	cd registry && test -z "$$(gofmt -l .)"

fmt-check: cli-fmt-check registry-fmt-check

workspace-check:
	python3 tools/workspace/workspace.py check

workspace-sync:
	python3 tools/workspace/workspace.py sync

docs-check:
	python3 tools/workspace/workspace.py docs-check

schema-check:
	python3 tools/workspace/workspace.py schema-check

examples-check:
	python3 tools/workspace/workspace.py examples-check

fixtures-check:
	python3 tools/workspace/workspace.py fixtures-check

audit-agent-check:
	test -f audit-agent/Dockerfile
	test -f audit-agent/Dockerfile.static
	test -f audit-agent/agent.js

audit-agent-image:
	cd registry && CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) go build -o ../audit-agent/registry-audit-agent ./cmd/audit-agent
	docker build -f audit-agent/Dockerfile.static -t rivet-audit-agent:local audit-agent
