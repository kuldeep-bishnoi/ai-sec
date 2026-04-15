package cli

import (
	"ai-sec/internal/ai"
	"ai-sec/internal/analyzers/goanalyzer"
	"ai-sec/internal/findings"
	"ai-sec/internal/patch"
	"ai-sec/internal/policy"
	"ai-sec/internal/rag"
	"ai-sec/internal/report"
	"ai-sec/internal/scanners/deps"
	"ai-sec/internal/scanners/sast"
	"ai-sec/internal/scanners/secrets"
	"ai-sec/internal/taint"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"
)

type scanOptions struct {
	format        string
	fix           bool
	policy        string
	llm           string
	quiet         bool
	showSecrets   bool
	hideSecrets   bool
	redactSecrets bool
	limit         int
	view          string
}

func newScanCmd() *cobra.Command {
	opts := &scanOptions{}
	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a repository for security issues (secrets, deps, SAST, Go run in parallel)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), cmd, opts, args[0])
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "text", "Output format: text|json")
	cmd.Flags().BoolVar(&opts.fix, "fix", false, "Apply safe patches when available")
	cmd.Flags().StringVar(&opts.policy, "policy", "", "OPA rego policy file to evaluate")
	// Default off: scan-time LLM calls are slow (one request per eligible finding).
	cmd.Flags().StringVar(&opts.llm, "llm", "off", "LLM for scan-time AI hints: off|ollama|gemini (off is fastest)")
	cmd.Flags().BoolVar(&opts.quiet, "quiet", false, "Suppress progress messages on stderr")
	// Show secrets by default (user requested). Use --hide-secrets to avoid printing secrets in logs/CI.
	cmd.Flags().BoolVar(&opts.showSecrets, "show-secrets", true, "Show secret values in output (DANGEROUS)")
	cmd.Flags().BoolVar(&opts.hideSecrets, "hide-secrets", false, "Do not print secret values in output")
	cmd.Flags().BoolVar(&opts.redactSecrets, "redact-secrets", false, "Force redaction of secrets in output")
	cmd.Flags().IntVar(&opts.limit, "limit", 50, "Max findings to print in text output (0 = unlimited)")
	cmd.Flags().StringVar(&opts.view, "view", "full", "Text view: full|compact")
	return cmd
}

func runScan(ctx context.Context, cmd *cobra.Command, opts *scanOptions, target string) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("scan target must be a directory")
	}

	rep := findings.Report{
		TargetPath:  abs,
		GeneratedAt: time.Now(),
		Findings:    []findings.Finding{},
	}

	// Supply-chain scanners (optional; skipped if tools not installed).
	showSecrets := opts.showSecrets && !opts.hideSecrets && !opts.redactSecrets
	// Safety default: if output is not a TTY, redact secrets unless user explicitly set --show-secrets.
	if f, ok := cmd.OutOrStdout().(*os.File); ok && !term.IsTerminal(int(f.Fd())) {
		if !cmd.Flags().Changed("show-secrets") {
			showSecrets = false
		}
	}

	// Run independent scanners in parallel (secrets, deps, SAST, Go). Semgrep uses cmd.Dir on the
	// repo path so we do not rely on process-wide Chdir (which would race under concurrency).
	var scanMu sync.Mutex
	var g errgroup.Group
	runPhase := func(name string, work func()) {
		g.Go(func() error {
			t0 := time.Now()
			if !opts.quiet {
				fmt.Fprintf(cmd.ErrOrStderr(), "ai-sec: [%s] …\n", name)
			}
			work()
			if !opts.quiet {
				fmt.Fprintf(cmd.ErrOrStderr(), "ai-sec: [%s] done (%s)\n", name, time.Since(t0).Round(time.Millisecond))
			}
			return nil
		})
	}

	runPhase("secrets (gitleaks)", func() {
		fs, err := secrets.ScanGitleaks(ctx, abs, showSecrets)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: gitleaks scan skipped: %v\n", err)
			return
		}
		scanMu.Lock()
		rep.Findings = append(rep.Findings, fs...)
		scanMu.Unlock()
	})
	runPhase("dependencies (syft/grype or cdxgen/grype)", func() {
		if fd, err := deps.ScanSyftGrype(ctx, abs); err == nil {
			scanMu.Lock()
			rep.Findings = append(rep.Findings, fd...)
			scanMu.Unlock()
			return
		}
		if fd2, err2 := deps.ScanCdxgenGrype(ctx, abs); err2 == nil {
			scanMu.Lock()
			rep.Findings = append(rep.Findings, fd2...)
			scanMu.Unlock()
			return
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: dependency scan skipped (syft/grype and cdxgen/grype unavailable)\n")
	})
	runPhase("SAST (semgrep)", func() {
		sf, err := sast.ScanSemgrep(ctx, abs)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: semgrep scan skipped: %v\n", err)
			return
		}
		scanMu.Lock()
		rep.Findings = append(rep.Findings, sf...)
		scanMu.Unlock()
	})
	runPhase("Go analysis (SSA + taint)", func() {
		ga, err := goanalyzer.Analyze(ctx, abs)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: go analysis skipped: %v\n", err)
			return
		}
		tr, err := taint.AnalyzeGo(ctx, ga.SSA.Fset, ga.SSA.Program)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: go taint analysis skipped: %v\n", err)
			return
		}
		scanMu.Lock()
		rep.Findings = append(rep.Findings, tr.Findings...)
		scanMu.Unlock()
	})
	_ = g.Wait()

	// Collapse duplicates (notably dependency matches that can repeat across manifests/paths).
	rep.Findings = findings.DedupeByID(rep.Findings)

	// AI remediation (best-effort). Uses RAG index or in-memory chunk fallback.
	if opts.llm != "off" {
		provider, err := ai.NewProvider(ai.ProviderParams{Mode: opts.llm})
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: llm: %v; skipping AI remediation\n", err)
		} else {
			var aiTargets []findings.Finding
			for _, f := range rep.Findings {
				if f.Source != findings.EngineTaint && f.Source != findings.EngineSecrets && f.Source != findings.EngineDeps {
					continue
				}
				aiTargets = append(aiTargets, f)
			}
			if !opts.quiet && len(aiTargets) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "ai-sec: [LLM %s] %d finding(s) to enrich (slow)…\n", provider.Name(), len(aiTargets))
			}
			tAI := time.Now()
			for i, f := range aiTargets {
				if !opts.quiet {
					fmt.Fprintf(cmd.ErrOrStderr(), "ai-sec: [LLM] %d/%d %s …\n", i+1, len(aiTargets), f.ID)
				}
				query := fmt.Sprintf("%s %s %s", f.Type, f.PrimaryLocation.File, f.Explanation)
				rr, err := rag.Retrieve(ctx, abs, query, 4)
				if err != nil {
					chunks, cErr := rag.ChunkRepository(abs, rag.DefaultChunkOptions())
					if cErr != nil {
						continue
					}
					rr = rag.RetrieveFromChunks(ctx, chunks, query, 4)
				}
				aiF, err := ai.GenerateRemediation(ctx, provider, f, rr.Chunks)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: AI remediation failed for %s: %v\n", f.ID, err)
					continue
				}
				rep.Findings = append(rep.Findings, aiF)
			}
			if !opts.quiet && len(aiTargets) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "ai-sec: [LLM] done (%s)\n", time.Since(tAI).Round(time.Millisecond))
			}
		}
	}

	// Dedupe again after AI adds findings.
	rep.Findings = findings.DedupeByID(rep.Findings)

	// Persist last report for `ai-sec explain`.
	_ = os.MkdirAll(filepath.Join(abs, ".ai-sec"), 0o755)
	if b, err := rep.MarshalJSON(); err == nil {
		_ = os.WriteFile(filepath.Join(abs, ".ai-sec", "last_report.json"), b, 0o644)
	}

	// Patch engine (safe-by-default).
	if opts.fix {
		for _, f := range rep.Findings {
			if f.Patch == nil || f.Patch.UnifiedDiff == "" {
				continue
			}
			if _, err := patch.ApplyUnifiedDiff(abs, f.Patch.UnifiedDiff); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: patch apply failed for %s: %v\n", f.ID, err)
			}
		}
	}

	var policyErr error
	if opts.policy != "" {
		dec, err := policy.EvaluateOPA(ctx, abs, opts.policy, rep)
		if err != nil {
			policyErr = err
		} else if len(dec.Deny) > 0 {
			for _, d := range dec.Deny {
				fmt.Fprintf(cmd.ErrOrStderr(), "policy deny: %s\n", d)
			}
			policyErr = fmt.Errorf("policy denied (%d)", len(dec.Deny))
		}
	}

	switch opts.format {
	case "text":
		if err := report.WriteTextWithOptions(cmd.OutOrStdout(), rep, report.TextOptions{Limit: opts.limit, View: opts.view}); err != nil {
			return err
		}
		return policyErr
	case "json":
		if err := report.WriteJSON(cmd.OutOrStdout(), rep); err != nil {
			return err
		}
		return policyErr
	default:
		return fmt.Errorf("unknown format %q (expected text|json)", opts.format)
	}
}
