package rag

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ChunkOptions struct {
	MaxLines int
	Overlap  int
	MaxBytes int
}

func DefaultChunkOptions() ChunkOptions {
	return ChunkOptions{
		MaxLines: 200,
		Overlap:  20,
		MaxBytes: 64 * 1024,
	}
}

func ChunkRepository(repoPath string, opts ChunkOptions) ([]Chunk, error) {
	var chunks []Chunk

	err := filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := filepath.Base(path)
			switch base {
			case ".git", "node_modules", "vendor", ".ai-sec":
				return filepath.SkipDir
			}
			return nil
		}

		lang := languageForFile(path)
		if lang == "" {
			return nil
		}

		fileChunks, err := chunkFile(path, repoPath, lang, opts)
		if err != nil {
			// Best-effort: skip unreadable/binary-ish files.
			return nil
		}
		chunks = append(chunks, fileChunks...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return chunks, nil
}

func languageForFile(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".java":
		return "java"
	case ".md":
		return "markdown"
	default:
		return ""
	}
}

func chunkFile(path string, repoRoot string, lang string, opts ChunkOptions) ([]Chunk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rel, _ := filepath.Rel(repoRoot, path)
	rel = filepath.ToSlash(rel)

	var lines []string
	var totalBytes int

	r := bufio.NewReader(f)
	for {
		s, err := r.ReadString('\n')
		if len(s) > 0 {
			s = strings.TrimRight(s, "\r\n")
			lines = append(lines, s)
			totalBytes += len(s)
			if opts.MaxBytes > 0 && totalBytes > opts.MaxBytes*200 { // hard cap per file
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}

	if len(lines) == 0 {
		return nil, nil
	}

	maxLines := opts.MaxLines
	if maxLines <= 0 {
		maxLines = 200
	}
	overlap := opts.Overlap
	if overlap < 0 {
		overlap = 0
	}
	step := maxLines - overlap
	if step <= 0 {
		step = maxLines
	}

	var chunks []Chunk
	for start := 0; start < len(lines); start += step {
		end := start + maxLines
		if end > len(lines) {
			end = len(lines)
		}
		text := strings.Join(lines[start:end], "\n")

		sum := sha256.Sum256([]byte(rel + ":" + lang + ":" + text))
		id := hex.EncodeToString(sum[:16])

		chunks = append(chunks, Chunk{
			ID:        id,
			File:      rel,
			StartLine: start + 1,
			EndLine:   end,
			Language:  lang,
			Text:      text,
		})
		if end == len(lines) {
			break
		}
	}
	return chunks, nil
}
