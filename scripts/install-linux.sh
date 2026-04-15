#!/usr/bin/env bash
# AI-Sec — Linux installer: installs ai-sec and optionally third-party OSS scanners.
# Usage: run from the repository root, or pass --binary to a prebuilt binary.
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BINARY_SRC=""
FROM_SOURCE=0
WITH_DEPS=""
WITH_OLLAMA=""
SKIP_MAIN=0

die() { echo "error: $*" >&2; exit 1; }

usage() {
	cat <<'EOF'
Usage: install-linux.sh [options]

  Installs ai-sec into INSTALL_DIR (default: ~/.local/bin) and optionally
  prompts to install OSS scanner dependencies (gitleaks, syft, grype, semgrep,
  cdxgen; optional ollama).

Options:
  --prefix DIR     Install directory (default: ~/.local/bin)
  --binary PATH    Copy this prebuilt ai-sec binary (skip build)
  --source         Build from source with Go (from repo root)
  --with-deps      Non-interactive: install ai-sec + scanner deps (not ollama)
  --with-ollama    With --with-deps: also install Ollama (large)
  --without-deps   Non-interactive: only install ai-sec
  --skip-main      Only run dependency installers (ai-sec binary must exist)
  -h, --help       Show this help

Environment:
  INSTALL_DIR      Same as --prefix

Examples:
  ./scripts/install-linux.sh --source
  ./scripts/install-linux.sh --binary ./dist/ai-sec-linux-amd64
  INSTALL_DIR=/usr/local/bin sudo -E ./scripts/install-linux.sh --binary ./ai-sec
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--prefix)
		INSTALL_DIR="${2:?}"
		shift 2
		;;
	--binary)
		BINARY_SRC="${2:?}"
		shift 2
		;;
	--source) FROM_SOURCE=1; shift ;;
	--with-deps) WITH_DEPS=yes; shift ;;
	--with-ollama) WITH_OLLAMA=yes; shift ;;
	--without-deps) WITH_DEPS=no; shift ;;
	--skip-main) SKIP_MAIN=1; shift ;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "unknown option: $1" ;;
	esac
done

[[ "$(uname -s)" == "Linux" ]] || die "this script is for Linux only"

mkdir -p "$INSTALL_DIR"
case ":$PATH:" in
*:"$INSTALL_DIR":*) ;;
*)
	echo "Note: add to your shell profile if needed:"
	echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
	;;
esac

install_ai_sec() {
	if [[ -n "$BINARY_SRC" ]]; then
		[[ -f "$BINARY_SRC" ]] || die "binary not found: $BINARY_SRC"
		cp -f "$BINARY_SRC" "$INSTALL_DIR/ai-sec"
		chmod +x "$INSTALL_DIR/ai-sec"
		echo "Installed ai-sec from $BINARY_SRC -> $INSTALL_DIR/ai-sec"
		return
	fi
	if [[ "$FROM_SOURCE" -eq 1 ]]; then
		command -v go >/dev/null 2>&1 || die "Go not found; install Go or use --binary"
		[[ -f cmd/ai-sec/main.go ]] || die "run from repository root (cmd/ai-sec/main.go missing)"
		(
			VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
			CGO_ENABLED=0 go build -trimpath \
				-ldflags "-s -w -X ai-sec/internal/cli.Version=$VERSION" \
				-o "$INSTALL_DIR/ai-sec" ./cmd/ai-sec
		)
		chmod +x "$INSTALL_DIR/ai-sec"
		echo "Built and installed ai-sec -> $INSTALL_DIR/ai-sec"
		return
	fi
	die "choose --binary PATH, --source (from repo), or see --help"
}

if [[ "$SKIP_MAIN" -eq 0 ]]; then
	install_ai_sec
fi

prompt_deps() {
	if [[ -n "$WITH_DEPS" ]]; then
		[[ "$WITH_DEPS" == "yes" ]] && return 0
		return 1
	fi
	echo
	read -r -p "Install optional OSS scanner tools (gitleaks, syft, grype, semgrep, cdxgen)? [y/N] " ans
	[[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

prompt_ollama() {
	if [[ "${WITH_OLLAMA:-}" == "yes" ]]; then
		return 0
	fi
	if [[ -n "${WITH_DEPS:-}" ]]; then
		# Bundled --with-deps skips Ollama unless --with-ollama
		return 1
	fi
	if [[ ! -t 0 ]]; then
		return 1
	fi
	echo
	read -r -p "Install Ollama (local LLM runtime, larger download)? [y/N] " ans
	[[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

run() {
	echo "+ $*"
	"$@" || echo "warning: command failed (continuing): $*"
}

install_syft_grype() {
	echo "== syft & grype (Anchore)"
	if command -v syft >/dev/null 2>&1 && command -v grype >/dev/null 2>&1; then
		echo "syft and grype already on PATH."
		return
	fi
	if command -v sudo >/dev/null 2>&1; then
		run curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
		run curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
	else
		mkdir -p "$HOME/.local/bin"
		run curl -sSfL https://get.anchore.io/syft | sh -s -- -b "$HOME/.local/bin"
		run curl -sSfL https://get.anchore.io/grype | sh -s -- -b "$HOME/.local/bin"
		echo "Installed syft/grype to $HOME/.local/bin — ensure it is on PATH."
	fi
}

install_gitleaks() {
	echo "== gitleaks"
	command -v gitleaks >/dev/null 2>&1 && echo "gitleaks already on PATH." && return
	local arch gl_arch tag url tmp
	arch="$(uname -m)"
	case "$arch" in
	x86_64) gl_arch=x64 ;;
	aarch64 | arm64) gl_arch=arm64 ;;
	*) echo "warning: unsupported arch for gitleaks: $arch"; return ;;
	esac
	tag="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -1)"
	[[ -n "$tag" ]] || {
		echo "warning: could not resolve gitleaks version"
		return
	}
	url="https://github.com/gitleaks/gitleaks/releases/download/v${tag}/gitleaks_${tag}_linux_${gl_arch}.tar.gz"
	tmp="$(mktemp -d)"
	cleanup() { rm -rf "$tmp"; }
	trap cleanup EXIT
	if ! curl -fsSL "$url" | tar xz -C "$tmp"; then
		echo "warning: gitleaks download failed: $url"
		trap - EXIT
		cleanup
		return
	fi
	if [[ -f "$tmp/gitleaks" ]]; then
		if [[ -w /usr/local/bin ]] 2>/dev/null; then
			install -m0755 "$tmp/gitleaks" /usr/local/bin/gitleaks
		elif command -v sudo >/dev/null 2>&1; then
			sudo install -m0755 "$tmp/gitleaks" /usr/local/bin/gitleaks
		else
			install -m0755 "$tmp/gitleaks" "$INSTALL_DIR/gitleaks"
			echo "Installed gitleaks to $INSTALL_DIR/gitleaks"
		fi
	else
		echo "warning: gitleaks binary not found in archive"
	fi
	trap - EXIT
	cleanup
}

install_semgrep() {
	echo "== semgrep"
	command -v semgrep >/dev/null 2>&1 && echo "semgrep already on PATH." && return
	if command -v pipx >/dev/null 2>&1; then
		run pipx install semgrep
		return
	fi
	if command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
		echo "Installing pipx via apt (needs sudo)..."
		run sudo DEBIAN_FRONTEND=noninteractive apt-get install -y pipx
		run pipx ensurepath
		run pipx install semgrep
		return
	fi
	echo "warning: install pipx, then: pipx install semgrep"
}

install_cdxgen() {
	echo "== cdxgen"
	command -v cdxgen >/dev/null 2>&1 && echo "cdxgen already on PATH." && return
	if command -v npm >/dev/null 2>&1; then
		run npm install -g @cyclonedx/cdxgen
		return
	fi
	echo "warning: Node.js/npm not found; install Node LTS then: npm i -g @cyclonedx/cdxgen"
}

install_ollama() {
	echo "== ollama"
	command -v ollama >/dev/null 2>&1 && echo "ollama already on PATH." && return
	run bash -c "$(curl -fsSL https://ollama.com/install.sh)"
}

if prompt_deps; then
	install_syft_grype
	install_gitleaks
	install_semgrep
	install_cdxgen
	if prompt_ollama; then
		install_ollama
	fi
	echo
	echo "Run: $INSTALL_DIR/ai-sec doctor"
else
	echo "Skipped OSS tools. Install later: ai-sec install-tools --yes  or  re-run this script."
fi

echo "Done."
