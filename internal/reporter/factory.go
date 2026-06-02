package reporter

import (
	"fmt"
	"io"
	"os"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type Format string

const (
	FormatText     Format = "text"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif"
	FormatMarkdown Format = "markdown"
)

// CLI flag'lerinden doldurulur.
type Options struct {
	Format      Format
	Output      string
	NoColor     bool
	Verbose     bool
	Pretty      bool // JSON pretty print
	RepoRoot    string
	ProjectName string
	FailOn      analyzer.Severity
}

func New(opts Options) (Reporter, io.WriteCloser, error) {
	// Output hedefini belirle
	var out io.WriteCloser
	if opts.Output == "" || opts.Output == "-" {
		out = nopCloser{os.Stdout}
	} else {
		f, err := os.Create(opts.Output)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot create output file: %w", err)
		}
		out = f
	}

	useColor := !opts.NoColor && isTerminal(os.Stdout) && opts.Output == ""

	var r Reporter
	switch opts.Format {
	case FormatText, "":
		r = NewText(out, useColor, opts.Verbose)
	case FormatJSON:
		r = NewJSON(out, opts.Pretty)
	case FormatSARIF:
		r = NewSARIF(out, opts.RepoRoot)
	case FormatMarkdown:
		r = NewMarkdown(out, opts.ProjectName)
	default:
		return nil, nil, fmt.Errorf("unknown format %q (valid: text, json, sarif, markdown)", opts.Format)
	}

	return r, out, nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
