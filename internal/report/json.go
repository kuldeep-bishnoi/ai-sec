package report

import (
	"ai-sec/internal/findings"
	"io"
)

func WriteJSON(w io.Writer, rep findings.Report) error {
	b, err := rep.MarshalJSON()
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
