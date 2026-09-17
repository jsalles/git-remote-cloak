// PackWriter: streaming encryption of a packfile (or any blob) into a temp
// file while hashing the ciphertext, yielding the content-addressed pack id
// (SHA-256 of ciphertext) and size used by the manifest. Shared by the push
// path and the seed-remote debug command.
package agecrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// ErrCiphertextLimit is returned when a limited PackWriter would write beyond
// its configured ciphertext cap. Callers use it to switch to bounded pack
// splitting rather than first materializing an arbitrarily large pack.
var ErrCiphertextLimit = errors.New("encrypted pack exceeds configured ciphertext limit")

// PackWriter encrypts plaintext written to it into a temp file. After
// Close, ID/Size/Path describe the finished ciphertext blob.
type PackWriter struct {
	w      io.WriteCloser
	f      *os.File
	hasher hash.Hash
	size   int64
	closed bool
	limit  int64
	over   bool
}

// counting wraps the file to count ciphertext bytes.
type counting struct {
	pw *PackWriter
}

func (c counting) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	write := p
	over := false
	if c.pw.limit > 0 {
		remaining := c.pw.limit - c.pw.size
		if remaining <= 0 {
			c.pw.over = len(p) > 0
			return 0, ErrCiphertextLimit
		}
		if int64(len(write)) > remaining {
			write = write[:remaining]
			over = true
		}
	}
	n, err := c.pw.f.Write(write)
	c.pw.hasher.Write(p[:n])
	c.pw.size += int64(n)
	if err == nil && n != len(write) {
		err = io.ErrShortWrite
	}
	if err == nil && over {
		c.pw.over = true
		err = ErrCiphertextLimit
	}
	return n, err
}

// NewPackWriter creates the temp file in dir and returns the encryptor.
func NewPackWriter(dir string, master keystore.Key) (*PackWriter, error) {
	return NewPackWriterLimited(dir, master, 0)
}

// NewPackWriterLimited creates a PackWriter whose ciphertext file never grows
// beyond maxBytes. maxBytes == 0 disables the limit.
func NewPackWriterLimited(dir string, master keystore.Key, maxBytes int64) (*PackWriter, error) {
	if maxBytes < 0 {
		return nil, fmt.Errorf("create limited pack writer: negative ciphertext limit %d", maxBytes)
	}
	f, err := os.CreateTemp(dir, "enc-*")
	if err != nil {
		return nil, fmt.Errorf("create pack encryption scratch file in %q: %w", dir, err)
	}
	pw := &PackWriter{f: f, hasher: sha256.New(), limit: maxBytes}
	w, err := Encrypt(counting{pw}, master)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, err
	}
	pw.w = w
	return pw, nil
}

// Write encrypts p.
func (p *PackWriter) Write(b []byte) (int, error) { return p.w.Write(b) }

// Close flushes the final STREAM chunk and closes the temp file.
func (p *PackWriter) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	if err := p.w.Close(); err != nil {
		_ = p.f.Close()
		return err
	}
	if err := p.f.Close(); err != nil {
		return fmt.Errorf("close pack encryption scratch file %q: %w", p.f.Name(), err)
	}
	return nil
}

// Abort removes the temp file (call when the pack is not used).
func (p *PackWriter) Abort() {
	_ = p.Close()
	_ = os.Remove(p.f.Name())
}

// LimitExceeded reports whether ciphertext output hit the configured cap.
func (p *PackWriter) LimitExceeded() bool { return p.over }

// ID is the hex SHA-256 of the ciphertext (valid after Close).
func (p *PackWriter) ID() string { return hex.EncodeToString(p.hasher.Sum(nil)) }

// Size is the ciphertext size in bytes (valid after Close).
func (p *PackWriter) Size() int64 { return p.size }

// Path is the temp file holding the ciphertext.
func (p *PackWriter) Path() string { return p.f.Name() }
