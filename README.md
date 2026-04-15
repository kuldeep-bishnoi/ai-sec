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

### Prebuilt binaries

After you publish [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository), users can download `ai-sec_*_linux_amd64.tar.gz` (and similar) and put the `ai-sec` binary on `PATH`.

### Build locally

```bash
make build         # ./bin/ai-sec
make install       # install to GOPATH/bin
make install-linux # Linux: chmod +x scripts/install-linux.sh && ./scripts/install-linux.sh --source
```

## After installation

1. **Confirm the binary** is on `PATH` (installer uses `~/.local/bin` by default):

   ```bash
   export PATH="$HOME/.local/bin:$PATH"   # add to ~/.bashrc or ~/.zshrc if needed
   ai-sec --version
   ```

2. **Check optional scanners** (gitleaks, syft, grype, semgrep, …):

   ```bash
   ai-sec doctor
   ai-sec install-tools              # print suggested install commands
   ai-sec install-tools --yes        # best-effort install (syft/grype on Linux)
   ```

## Run commands (by workflow)

All examples use `--repo` when the scan target is not the current directory. Reports and indexes are stored under `<repo>/.ai-sec/`.

### Scan a repository

```bash
# Text report (default) — compact list, limited rows
ai-sec scan /path/to/repo --format text --view compact --limit 50

# JSON output (good for piping)
ai-sec scan /path/to/repo --format json

# Progress only on stderr; no LLM during scan (default)
ai-sec scan /path/to/repo --format text --quiet

# Optional: Gemini scan-time hints (needs GOOGLE_API_KEY or GEMINI_API_KEY)
ai-sec scan /path/to/repo --llm gemini

# Secrets: hide values in output; force redaction in CI
ai-sec scan /path/to/repo --hide-secrets
ai-sec scan /path/to/repo --redact-secrets

# Policy (OPA Rego)
ai-sec scan /path/to/repo --policy /path/to/policy.rego
```

### List findings and inspect details

Requires a prior scan (writes `.ai-sec/last_report.json`).

```bash
ai-sec findings --repo /path/to/repo
ai-sec findings --repo /path/to/repo --severity CRITICAL,HIGH
ai-sec findings --repo /path/to/repo --source sast,taint

ai-sec show <finding_id> --repo /path/to/repo
```

### Explain or remediate (LLM)

```bash
# Re-explain a finding (ollama or gemini)
ai-sec explain <finding_id> --repo /path/to/repo --llm gemini

# Remediation: Gemini (set API key in the environment)
export GOOGLE_API_KEY=...
ai-sec remediate <finding_id> --repo /path/to/repo --llm gemini --gemini-model gemini-flash-latest --strict

# Remediation: local Ollama
ai-sec remediate <finding_id> --repo /path/to/repo --llm ollama --ollama-url http://127.0.0.1:11434 --ollama-timeout 300

# Apply generated patch only after strict validation passes
ai-sec remediate <finding_id> --repo /path/to/repo --llm gemini --strict --apply
```

### RAG index (optional, for embeddings)

```bash
ai-sec index /path/to/repo --embeddings
ai-sec index /path/to/repo --embeddings --ollama-url http://127.0.0.1:11434 --ollama-embed-model nomic-embed-text
```

## Optional external tools

Scanners call `gitleaks`, `syft`, `grype`, `cdxgen`, `semgrep`, and `opa` when installed. Use `ai-sec doctor` and `ai-sec install-tools` for guidance. On Linux, `./scripts/install-linux.sh` can install them interactively alongside `ai-sec`.
