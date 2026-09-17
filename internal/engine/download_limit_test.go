// Tests for receive-side pack bounds. Remote pack blobs are untrusted even
// when the manifest is authentic, so writes must stop at the recorded size and
// the local configured ceiling must be checked before any backend read.
package engine

import (
	"bytes"
	"errors"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/config"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

func TestExactSizeWriterStopsAtManifestSize(t *testing.T) {
	var dst bytes.Buffer
	w := &exactSizeWriter{dst: &dst, expected: 4}
	n, err := w.Write([]byte("abcdef"))
	if !errors.Is(err, errPackExceedsRecordedSize) {
		t.Fatalf("Write error = %v, want errPackExceedsRecordedSize", err)
	}
	if n != 4 || w.written != 4 || !w.overflow || dst.String() != "abcd" {
		t.Fatalf("bounded write = n:%d written:%d overflow:%v data:%q", n, w.written, w.overflow, dst.String())
	}
}

func TestExactSizeWriterAcceptsExactSize(t *testing.T) {
	var dst bytes.Buffer
	w := &exactSizeWriter{dst: &dst, expected: 4}
	if n, err := w.Write([]byte("abcd")); err != nil || n != 4 {
		t.Fatalf("exact Write = (%d, %v), want (4, nil)", n, err)
	}
	if w.written != 4 || w.overflow || dst.String() != "abcd" {
		t.Fatalf("exact write state = written:%d overflow:%v data:%q", w.written, w.overflow, dst.String())
	}
}

func TestDownloadVerifyPackChecksLocalReceiveLimitFirst(t *testing.T) {
	e := &Engine{Cfg: config.Config{MaxPackBytes: 100}}
	p := manifest.Pack{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 101}
	err := e.downloadVerifyPack("unused", "unused", p)
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.TooLarge {
		t.Fatalf("receive-limit error = %v, want TooLarge", err)
	}
}
