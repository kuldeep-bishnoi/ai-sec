# AI-Sec — build and release helpers
.PHONY: build install install-linux test clean dist

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-dev")
LDFLAGS := -s -w -X ai-sec/internal/cli.Version=$(VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ai-sec ./cmd/ai-sec

install:
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/ai-sec

# Interactive Linux installer (builds ai-sec + optional OSS tools)
install-linux:
	chmod +x scripts/install-linux.sh
	./scripts/install-linux.sh --source

test:
	go test ./...

clean:
	rm -rf bin dist

# Cross-compile common targets into ./dist (no CGO — pure Go CLI)
dist: clean
	mkdir -p dist
	@for pair in \
		linux/amd64 \
		linux/arm64 \
		darwin/amd64 \
		darwin/arm64 \
		windows/amd64; do \
		GOOS=$${pair%%/*}; \
		GOARCH=$${pair##*/}; \
		out=ai-sec-$${GOOS}-$${GOARCH}; \
		if [ "$$GOOS" = windows ]; then out=$$out.exe; fi; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$out ./cmd/ai-sec; \
	done
	@(cd dist && sha256sum * > checksums.txt 2>/dev/null || shasum -a 256 * > checksums.txt)
