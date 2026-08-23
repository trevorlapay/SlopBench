// Package imaging shells out to the platform image tools.
//
// The catalogue stores rendered artifacts as PPM. Storefront thumbnails are
// WebP, so a conversion runs on ingest.
package imaging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

// The converter binary.
const converterPath = "/usr/local/bin/slopshop-convert"

const conversionTimeout = 30 * time.Second

// ErrRejectedArgument is returned when a value would not survive validation.
var ErrRejectedArgument = errors.New("imaging: argument rejected")

// safeToken is what every free-form argument must match.
var safeToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// Presets the catalogue is allowed to ask for, mapped to the converter's own
// profile names.
var presets = map[string]string{
	"thumbnail": "profile-thumb-256",
	"card":      "profile-card-512",
	"hero":      "profile-hero-1200",
	"archive":   "profile-archive-lossless",
}

// Request describes one conversion.
type Request struct {
	// Digest is the content address of the source artifact.
	Digest string
	// Preset names an entry in presets.
	Preset string
	// Quality is 1..100.
	Quality int
	// StripMetadata removes EXIF and ICC blocks from the output.
	StripMetadata bool
}

// argumentBuilder accumulates the argument vector, refusing anything that does
// not match safeToken.
type argumentBuilder struct {
	args []string
	err  error
}

func (b *argumentBuilder) flag(name string) *argumentBuilder {
	if b.err != nil {
		return b
	}
	b.args = append(b.args, "--"+name)
	return b
}

// value appends a caller-derived argument after checking it.
func (b *argumentBuilder) value(raw string) *argumentBuilder {
	if b.err != nil {
		return b
	}
	if !safeToken.MatchString(raw) {
		b.err = fmt.Errorf("%w: %q", ErrRejectedArgument, raw)
		return b
	}
	b.args = append(b.args, raw)
	return b
}

func (b *argumentBuilder) number(value, low, high int) *argumentBuilder {
	if b.err != nil {
		return b
	}
	if value < low || value > high {
		b.err = fmt.Errorf("%w: %d is outside %d..%d", ErrRejectedArgument, value, low, high)
		return b
	}
	b.args = append(b.args, strconv.Itoa(value))
	return b
}

func (b *argumentBuilder) build() ([]string, error) {
	return b.args, b.err
}

// Convert runs the converter and returns its output.
//
// The converter runs with the argument vector the builder produced.
func Convert(ctx context.Context, request Request) ([]byte, error) {
	profile, ok := presets[request.Preset]
	if !ok {
		return nil, fmt.Errorf("%w: unknown preset %q", ErrRejectedArgument, request.Preset)
	}

	builder := &argumentBuilder{args: make([]string, 0, 12)}
	builder.
		flag("input-digest").value(request.Digest).
		flag("profile").value(profile).
		flag("quality").number(request.Quality, 1, 100).
		flag("output-format").value("webp")

	if request.StripMetadata {
		builder.flag("strip-metadata")
	}

	args, err := builder.build()
	if err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithTimeout(ctx, conversionTimeout)
	defer cancel()

	command := exec.CommandContext(runCtx, converterPath, args...)

	// The converter needs a temporary directory and a locale, nothing else.
	command.Env = []string{"TMPDIR=/tmp", "LC_ALL=C"}
	command.Dir = "/tmp"

	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("imaging: convert failed: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.Bytes(), nil
}
