package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/screensession"
)

// filesHarness collects what the agent sends to the console.
type filesHarness struct {
	mu     sync.Mutex
	frames []screensession.Frame
}

func (h *filesHarness) send(b []byte) error {
	var dec screensession.Decoder
	frames, err := dec.Feed(b)
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, f := range frames {
		f.Data = append([]byte(nil), f.Data...)
		h.frames = append(h.frames, f)
	}
	return err
}

func (h *filesHarness) wait(t *testing.T, op byte) screensession.Frame {
	t.Helper()
	for range 200 {
		h.mu.Lock()
		for _, f := range h.frames {
			if f.Op == op {
				h.mu.Unlock()
				return f
			}
		}
		h.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no frame with op %d", op)
	return screensession.Frame{}
}

func newFiles(dir string, h *filesHarness) *screenFiles {
	return &screenFiles{maxBytes: 1 << 20, desktop: func() (string, error) { return dir, nil }, send: h.send,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), notify: func(string) {}}
}

func fileFrame(op byte, data []byte) screensession.Frame {
	return screensession.Frame{Kind: screensession.File, Op: op, Data: data}
}

func TestScreenFilePut(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.pdf"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &filesHarness{}
	f := newFiles(dir, h)
	content := bytes.Repeat([]byte("x"), 100_000)
	head, _ := json.Marshal(map[string]any{"name": `..\..\report.pdf`, "size": len(content)})
	ctx := context.Background()
	f.handle(ctx, fileFrame(screensession.FilePut, head))
	for i := 0; i < len(content); i += screensession.FileChunk {
		f.handle(ctx, fileFrame(screensession.FilePutData, content[i:min(i+screensession.FileChunk, len(content))]))
	}
	f.handle(ctx, fileFrame(screensession.FilePutEnd, nil))
	var r fileResult
	_ = json.Unmarshal(h.wait(t, screensession.FileResult).Data, &r)
	want := filepath.Join(dir, "report (2).pdf")
	if !r.OK || r.Path != want {
		t.Fatalf("result = %+v, want %s", r, want)
	}
	if got, _ := os.ReadFile(want); !bytes.Equal(got, content) {
		t.Fatal("content differs")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".tempra-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestScreenFilePutRefused(t *testing.T) {
	for name, head := range map[string]map[string]any{
		"too_large": {"name": "big.iso", "size": 2 << 20},
		"bad_name":  {"name": "CON", "size": 1},
	} {
		h := &filesHarness{}
		f := newFiles(t.TempDir(), h)
		b, _ := json.Marshal(head)
		f.handle(context.Background(), fileFrame(screensession.FilePut, b))
		var r fileResult
		_ = json.Unmarshal(h.wait(t, screensession.FileResult).Data, &r)
		if r.OK || r.Code != name {
			t.Fatalf("%s: result = %+v", name, r)
		}
	}
}

func TestScreenFileGet(t *testing.T) {
	dir := t.TempDir()
	content := bytes.Repeat([]byte("abc"), 50_000)
	path := filepath.Join(dir, "log.txt")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	h := &filesHarness{}
	f := newFiles(dir, h)
	req, _ := json.Marshal(map[string]string{"path": `"` + path + `"`})
	f.handle(context.Background(), fileFrame(screensession.FileGet, req))
	h.wait(t, screensession.FileGetEnd)
	var got []byte
	h.mu.Lock()
	for _, fr := range h.frames {
		if fr.Op == screensession.FileGetData {
			got = append(got, fr.Data...)
		}
	}
	h.mu.Unlock()
	if !bytes.Equal(got, content) {
		t.Fatalf("got %d bytes, want %d", len(got), len(content))
	}

	h2 := &filesHarness{}
	f2 := newFiles(dir, h2)
	req, _ = json.Marshal(map[string]string{"path": filepath.Join(dir, "missing.txt")})
	f2.handle(context.Background(), fileFrame(screensession.FileGet, req))
	var r fileResult
	_ = json.Unmarshal(h2.wait(t, screensession.FileResult).Data, &r)
	if r.OK || r.Code != "not_found" {
		t.Fatalf("result = %+v", r)
	}
}
