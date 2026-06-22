.PHONY: test fmt-check cli-test registry-test

test: cli-test registry-test

cli-test:
	cd cli && cargo test

registry-test:
	cd registry && go test ./...

fmt-check:
	cd cli && cargo fmt --check
	cd registry && test -z "$$(gofmt -l .)"

