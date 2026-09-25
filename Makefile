.PHONY: test fmt-check cli-test cli-clippy cli-fmt-check registry-test registry-test-postgres registry-fmt-check audit-agent-check audit-agent-image workspace-check workspace-sync docs-check schema-check examples-check fixtures-check e2e

test: workspace-check cli-test registry-test

cli-test:
	cd cli && cargo test

cli-clippy:
	cd cli && cargo clippy --all-targets -- -D warnings

cli-fmt-check:
	cd cli && cargo fmt --check

registry-test:
	cd registry && go test ./...

# Runs the store contract against a disposable database, e.g.
# RIVET_TEST_DATABASE_URL=postgres://rivet:rivet@localhost:5432/rivet_test?sslmode=disable
registry-test-postgres:
	test -n "$$RIVET_TEST_DATABASE_URL"
	cd registry && go test ./internal/db/ -run '^(TestPostgresStoreContract|TestLegacyReleaseWithoutDigestBlocksStartup)$$' -v

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
	node --check audit-agent/agent.js
	node --check audit-agent/egress-hook.js

audit-agent-image:
	docker build -f audit-agent/Dockerfile -t rivet-audit-agent:local audit-agent

# Live end-to-end run against registry.npmjs.org (needs network, Go, Rust, Node).
e2e:
	tools/e2e/npm-port.sh
