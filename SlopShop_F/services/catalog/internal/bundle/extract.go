//go:build unix

// Package bundle unpacks seller import archives.
//
// A seller uploads a tar.gz of listing images and a manifest. Entry names,
// types, sizes and counts are checked before anything is written.
package bundle

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// MaxEntries bounds how many members one archive may contain.
	MaxEntries = 2000
	// MaxEntryBytes bounds a single member.
	MaxEntryBytes = 32 << 20
	// MaxTotalBytes bounds the expanded archive, so a highly compressible
	// archive cannot fill the disk.
	MaxTotalBytes = 512 << 20

	entryMode     os.FileMode = 0o600
	directoryMode os.FileMode = 0o700
)

var (
	// ErrUnsafeEntry is returned for a member whose name would place it outside
	// the destination.
	ErrUnsafeEntry = errors.New("bundle: entry escapes the destination")
	// ErrUnsupportedEntry is returned for a member that is not a regular file
	// or a directory.
	ErrUnsupportedEntry = errors.New("bundle: unsupported entry type")
	// ErrTooLarge is returned when a bound is exceeded.
	ErrTooLarge = errors.New("bundle: archive exceeds a size limit")
)

// Result summarises one extraction.
type Result struct {
	Files int
	Bytes int64
}

// resolve turns an archive entry name into an absolute path underneath root.
//
// Absolute names, volume names and names that still begin with a parent
// reference after cleaning are refused; what is left is joined onto root.
func resolve(root, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: empty name", ErrUnsafeEntry)
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") || filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("%w: absolute name %q", ErrUnsafeEntry, name)
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: name contains a null byte", ErrUnsafeEntry)
	}

	cleaned := filepath.Clean(filepath.FromSlash(name))
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %q", ErrUnsafeEntry, name)
	}

	joined := filepath.Join(root, cleaned)

	prefix := root
	if !strings.HasSuffix(prefix, string(os.PathSeparator)) {
		prefix += string(os.PathSeparator)
	}
	if joined != root && !strings.HasPrefix(joined, prefix) {
		return "", fmt.Errorf("%w: %q", ErrUnsafeEntry, name)
	}

	return joined, nil
}

// Extract unpacks the archive read from r into destination.
//
// destination must already exist. Only regular files and directories are
// unpacked.
func Extract(r io.Reader, destination string) (Result, error) {
	root, err := filepath.Abs(destination)
	if err != nil {
		return Result{}, fmt.Errorf("bundle: resolve destination: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return Result{}, fmt.Errorf("bundle: stat destination: %w", err)
	}
	if !info.IsDir() {
		return Result{}, errors.New("bundle: destination is not a directory")
	}

	gzipReader, err := gzip.NewReader(io.LimitReader(r, MaxTotalBytes))
	if err != nil {
		return Result{}, fmt.Errorf("bundle: open archive: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	var result Result
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, fmt.Errorf("bundle: read entry: %w", err)
		}

		if result.Files >= MaxEntries {
			return result, fmt.Errorf("%w: more than %d entries", ErrTooLarge, MaxEntries)
		}

		switch header.Typeflag {
		case tar.TypeDir, tar.TypeReg:
			// Handled below.
		default:
			return result, fmt.Errorf("%w: %q is type %d",
				ErrUnsupportedEntry, header.Name, header.Typeflag)
		}

		target, err := resolve(root, header.Name)
		if err != nil {
			return result, err
		}

		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, directoryMode); err != nil {
				return result, fmt.Errorf("bundle: create directory: %w", err)
			}
			continue
		}

		if header.Size < 0 || header.Size > MaxEntryBytes {
			return result, fmt.Errorf("%w: %q declares %d bytes",
				ErrTooLarge, header.Name, header.Size)
		}
		if result.Bytes+header.Size > MaxTotalBytes {
			return result, fmt.Errorf("%w: expanded archive exceeds %d bytes",
				ErrTooLarge, MaxTotalBytes)
		}

		written, err := writeRegular(target, tarReader, header.Size)
		if err != nil {
			return result, err
		}

		result.Files++
		result.Bytes += written
	}

	return result, nil
}

// writeRegular creates one file and copies at most declared bytes into it.
//
// The file must not already exist and must not be a symbolic link.
func writeRegular(target string, source io.Reader, declared int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(target), directoryMode); err != nil {
		return 0, fmt.Errorf("bundle: create parent: %w", err)
	}

	file, err := os.OpenFile(
		target,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,
		entryMode,
	)
	if err != nil {
		return 0, fmt.Errorf("bundle: create file: %w", err)
	}
	defer file.Close()

	written, err := io.Copy(file, io.LimitReader(source, declared))
	if err != nil {
		return written, fmt.Errorf("bundle: write file: %w", err)
	}
	if written != declared {
		return written, fmt.Errorf("bundle: entry was truncated")
	}
	return written, nil
}
