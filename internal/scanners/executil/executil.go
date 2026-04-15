package executil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

func Run(ctx context.Context, name string, args ...string) (Result, error) {
	return RunDir(ctx, "", name, args...)
}

// RunDir runs a command with working directory dir (empty means current directory).
func RunDir(ctx context.Context, dir string, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()

	res := Result{
		Stdout: outBuf.Bytes(),
		Stderr: errBuf.Bytes(),
		ExitCode: func() int {
			if err == nil {
				return 0
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			return -1
		}(),
	}

	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			return res, fmt.Errorf("%s not found in PATH", name)
		}
		return res, err
	}
	return res, nil
}
