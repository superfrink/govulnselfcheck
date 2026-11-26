# Local commands match CI exactly, so a green `make check` means a green run.
# The race detector is part of `test`, not an optional extra: this library has
# a cache, a bounded worker pool and a periodic loop, and every one of them has
# concurrency that a plain `go test` never exercises under the detector.
#
# -race needs cgo, so a C compiler (gcc or clang) must be installed.

GO ?= go
FLOOR ?= 88

.PHONY: all check fmt vet test test-once cover build example clean

all: check

check: fmt vet test

fmt:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "not gofmt'd:"; echo "$$unformatted"; exit 1; fi

vet:
	$(GO) vet ./...

# -shuffle=on rotates test order, so a test that only passes in file order is
# caught here rather than in someone else's checkout.
test:
	$(GO) test -race -shuffle=on ./...

# One pass, no shuffle: the reproducible run to quote in a report.
test-once:
	$(GO) test -race -count=1 ./...

cover:
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out | tail -1
	@total=$$($(GO) tool cover -func=coverage.out | tail -1 | awk '{print $$3}' | tr -d '%'); \
	awk -v c="$$total" -v f="$(FLOOR)" 'BEGIN{ if (c+0 < f+0) { printf "coverage %.1f%% is below the %s%% floor\n", c, f; exit 1 } }'

build:
	$(GO) build ./...

example:
	$(GO) build -o govulnselfcheck ./examples/selfcheck-cli

clean:
	rm -f coverage.out govulnselfcheck
