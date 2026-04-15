# AI-Sec

AI-assisted security scanner CLI (secrets, dependencies, Semgrep, Go taint analysis, optional LLM remediation).

## Install

### Linux: guided installer (recommended)

From a clone of this repository on **Linux**:

```bash
chmod +x scripts/install-linux.sh
./scripts/install-linux.sh --source
```

This installs `ai-sec` into `~/.local/bin` (override with `INSTALL_DIR` or `--prefix`) and **prompts** to install optional OSS scanners (gitleaks, syft, grype, opa, semgrep, cdxgen; optional Ollama).

Non-interactive examples:

```bash
# Only the ai-sec binary
./scripts/install-linux.sh --source --without-deps

# Binary + all scanner deps (not Ollama)
./scripts/install-linux.sh --source --with-deps

# Same, plus Ollama
./scripts/install-linux.sh --source --with-deps --with-ollama

# Prebuilt binary from make dist
./scripts/install-linux.sh --binary ./dist/ai-sec-linux-amd64 --with-deps
```

Third-party tools are downloaded from their official installers or GitHub releases; review the script before running in production.

### From source (Go 1.21+)

From a clone of this repository:

```bash
go install ./cmd/ai-sec
```

After you publish the module under a public path (see below), others can run:

```bash
go install github.com/YOUR_ORG/ai-sec/cmd/ai-sec@latest
```

Ensure `$(go env GOPATH)/bin` is on your `PATH`.

### Prebuilt binaries

After you publish [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository), users can download `ai-sec_*_linux_amd64.tar.gz` (and similar) and put the `ai-sec` binary on `PATH`.

### Build locally

```bash
make build    # ./bin/ai-sec
make install  # install to GOPATH/bin
```

## Publish for the public

1. **Push the repo** to GitHub (or GitLab) and pick an **open-source license** (e.g. MIT, Apache-2.0).
2. **Tag a release**: `git tag v1.0.0 && git push origin v1.0.0`
3. **Ship binaries** (pick one):
   - **GoReleaser** (recommended): install [GoReleaser](https://goreleaser.com/install/), set `GITHUB_TOKEN`, run `goreleaser release --clean` (often via GitHub Actions on tag).
   - **Manual**: run `make dist` and upload files under `dist/` plus `checksums.txt` to the release page.

4. **Module path**: replace `ai-sec` in `go.mod` with your module path (e.g. `github.com/you/ai-sec`) so `go install` works for others.

## Optional external tools

Scanners call `gitleaks`, `syft`, `grype`, `cdxgen`, `semgrep`, and `opa` when installed. Use `ai-sec doctor` and `ai-sec install-tools` for guidance.
