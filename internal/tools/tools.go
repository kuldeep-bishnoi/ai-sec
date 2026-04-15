package tools

import (
	"ai-sec/internal/scanners/executil"
	"context"
	"fmt"
	"strings"
)

type Status string

const (
	StatusOK      Status = "ok"
	StatusMissing Status = "missing"
	StatusBroken  Status = "broken"
)

type ToolCheck struct {
	Name        string
	Command     string
	Args        []string
	InstallHint string
}

type ToolResult struct {
	Name    string
	Status  Status
	Details string
}

func DefaultChecks() []ToolCheck {
	return []ToolCheck{
		{
			Name:    "gitleaks",
			Command: "gitleaks",
			Args:    []string{"version"},
			InstallHint: "Install gitleaks (examples):\n" +
				"- apt (if available): `sudo apt-get install -y gitleaks`\n" +
				"- or release binary: `https://github.com/gitleaks/gitleaks`",
		},
		{
			Name:        "syft",
			Command:     "syft",
			Args:        []string{"version"},
			InstallHint: "Install syft: `curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin`",
		},
		{
			Name:        "grype",
			Command:     "grype",
			Args:        []string{"version"},
			InstallHint: "Install grype: `curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin`",
		},
		{
			Name:    "cdxgen",
			Command: "cdxgen",
			Args:    []string{"--version"},
			InstallHint: "Install cdxgen:\n" +
				"- global: `npm i -g @cyclonedx/cdxgen`\n" +
				"- or run without install: `npx @cyclonedx/cdxgen -o sbom.cdx.json`",
		},
		{
			Name:    "semgrep",
			Command: "semgrep",
			Args:    []string{"--version"},
			InstallHint: "Install semgrep (your distro may not package it):\n" +
				"- via pipx: `sudo apt-get install -y pipx && pipx install semgrep`\n" +
				"- or venv: `python3 -m venv ~/.venvs/semgrep && ~/.venvs/semgrep/bin/pip install semgrep`",
		},
		{
			Name:        "opa",
			Command:     "opa",
			Args:        []string{"version"},
			InstallHint: "Install opa: `https://www.openpolicyagent.org/docs/latest/#running-opa`",
		},
		{
			Name:        "ollama",
			Command:     "ollama",
			Args:        []string{"--version"},
			InstallHint: "Install ollama: `https://ollama.com`",
		},
	}
}

func CheckAll(ctx context.Context, checks []ToolCheck) []ToolResult {
	out := make([]ToolResult, 0, len(checks))
	for _, c := range checks {
		res, err := executil.Run(ctx, c.Command, c.Args...)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "not found in PATH") {
				out = append(out, ToolResult{Name: c.Name, Status: StatusMissing, Details: c.InstallHint})
				continue
			}
			out = append(out, ToolResult{Name: c.Name, Status: StatusBroken, Details: fmt.Sprintf("%s\n%s", msg, c.InstallHint)})
			continue
		}
		details := strings.TrimSpace(string(res.Stdout))
		if details == "" {
			details = strings.TrimSpace(string(res.Stderr))
		}
		out = append(out, ToolResult{Name: c.Name, Status: StatusOK, Details: details})
	}
	return out
}
