package discover

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const maxZstdWindow = 64 << 20

// Open opens a discovered artifact for reading, transparently decompressing it
// when the path is a zstd-compressed rollout (.jsonl.zst). Codex background-
// compresses cold session files to .jsonl.zst; an extractor only ever sees
// plain JSONL, so decompression is handled here at the filesystem boundary,
// keeping every parser pure (operating on uncompressed bytes regardless of how
// the artifact was stored).
//
// The returned ReadCloser owns both the file handle and, for compressed
// artifacts, the decoder; closing it releases both. The caller must Close it.
func Open(path string) (io.ReadCloser, error) {
	return openPath(path, path)
}

// OpenArtifact opens an artifact returned by Walk. For a symlinked artifact it
// uses the target resolved during discovery, preventing a later link retarget
// from changing what the scan reads.
func OpenArtifact(artifact Artifact) (io.ReadCloser, error) {
	readPath := artifact.readPath
	if readPath == "" {
		readPath = artifact.Path
	}
	return openPath(readPath, artifact.Path)
}

func openPath(readPath, formatPath string) (io.ReadCloser, error) {
	f, err := openRegular(readPath)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(strings.ToLower(filepath.Base(formatPath)), ".jsonl.zst") {
		return f, nil
	}
	dec, err := zstd.NewReader(f,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxMemory(maxZstdWindow),
		zstd.WithDecoderMaxWindow(maxZstdWindow),
	)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &zstdReadCloser{dec: dec, f: f}, nil
}

// zstdReadCloser couples a zstd decoder to its underlying file so a single
// Close releases both. zstd.Decoder.Close returns no error; the file's close
// error is the one surfaced.
type zstdReadCloser struct {
	dec *zstd.Decoder
	f   *os.File
}

func (z *zstdReadCloser) Read(p []byte) (int, error) { return z.dec.Read(p) }

func (z *zstdReadCloser) Close() error {
	z.dec.Close()
	return z.f.Close()
}
