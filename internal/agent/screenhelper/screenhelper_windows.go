//go:build windows

package screenhelper

import (
	"bytes"
	"context"
	"image"
	"image/jpeg"
	"io"
	"log"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/screensession"
)

// frameInterval caps the capture rate: fast enough to feel live, slow
// enough not to flood the session's channel with multi-hundred-KB frames.
const frameInterval = 150 * time.Millisecond

// jpegQuality trades detail for bandwidth; the operator is watching a
// desktop, not inspecting a photo.
const jpegQuality = 55

// clipboardInterval is how often the remote clipboard is checked for a
// change to send to the operator.
const clipboardInterval = 300 * time.Millisecond

// lockedWriter keeps the frames written by the capture and clipboard
// loops whole.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// Run captures the screen and injects input until stdin closes (the
// agent closes it when the session ends) or ctx is done. With
// shareClipboard, text pasted by the operator goes to the clipboard and
// text copied during the session comes back. It never returns an error
// for a session that simply ended normally.
func Run(stdin io.Reader, stdout io.Writer, shareClipboard bool) error {
	setDPIAware()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := &lockedWriter{w: stdout}
	if _, err := out.Write(screensession.EncodePolicy(shareClipboard)); err != nil {
		return err
	}
	// The clipboard as it was before the session is never sent: only
	// what changes from now on.
	var seen atomic.Uint32
	seen.Store(clipboardSeq())
	if shareClipboard {
		go clipboardLoop(ctx, out, &seen)
	}
	v := &view{}
	v.monitor.Store(screensession.AllMonitors)
	go captureLoop(ctx, out, v)

	dec := screensession.Decoder{}
	buf := make([]byte, 4096)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			frames, derr := dec.Feed(buf[:n])
			if derr != nil {
				return derr
			}
			for _, f := range frames {
				switch f.Kind {
				case screensession.Clip:
					// Set before the next frame (the operator's Ctrl+V)
					// is injected.
					if shareClipboard {
						pasteText(string(f.Text), &seen)
					}
				case screensession.View:
					v.monitor.Store(int32(f.Monitor))
					v.refresh.Store(true)
				case screensession.Refresh:
					v.refresh.Store(true)
				case screensession.Move:
					// Relative to the monitor shown.
					f.X += v.offX.Load()
					f.Y += v.offY.Load()
					applyInput(f)
				default:
					applyInput(f)
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// pasteText puts the operator's text on the clipboard, with Windows line
// ends, and marks that change as already seen so it is not sent back.
func pasteText(text string, seen *atomic.Uint32) {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
	if err := writeClipboard(text); err != nil {
		log.Printf("screenhelper: clipboard: %v", err)
	}
	seen.Store(clipboardSeq())
}

// clipboardLoop sends the clipboard text whenever it changes.
func clipboardLoop(ctx context.Context, out io.Writer, seen *atomic.Uint32) {
	ticker := time.NewTicker(clipboardInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		seq := clipboardSeq()
		if old := seen.Load(); seq == old || !seen.CompareAndSwap(old, seq) {
			continue
		}
		// Every UTF-16 code unit is at most 3 bytes of UTF-8.
		text, err := readClipboard(screensession.MaxClipboardSize / 3)
		if err != nil {
			if err != errNoText {
				log.Printf("screenhelper: clipboard: %v", err)
			}
			continue
		}
		if _, err := out.Write(screensession.EncodeClipboard([]byte(text))); err != nil {
			return
		}
	}
}

// applyInput injects an input event on the desktop thread, the only one
// on the input desktop. SAS frames are the agent's to act on: ignored.
func applyInput(f screensession.Frame) {
	onDesktopThread(func() { injectInput(f) })
}

func injectInput(f screensession.Frame) {
	var err error
	switch f.Kind {
	case screensession.Move:
		err = moveMouse(f.X, f.Y)
	case screensession.Button:
		err = mouseButton(f.Button, f.Down)
	case screensession.Wheel:
		err = mouseWheelInput(f.Wheel)
	case screensession.Key:
		err = keyInput(f.Key, f.Down)
	case screensession.Unicode:
		err = unicodeInput(f.Rune)
	}
	if err != nil {
		log.Printf("screenhelper: input: %v", err)
	}
}

// view is what the operator is shown: one monitor or all of them, and
// where it sits in the virtual desktop (to place the mouse).
type view struct {
	monitor    atomic.Int32 // index in the last monitor list, or AllMonitors
	refresh    atomic.Bool  // send everything again
	offX, offY atomic.Int32
}

// captureLoop sends the screen: the monitor list, the size of the part
// shown, then only the parts that changed since the previous frame, each
// as its own JPEG. Nothing is sent while the screen does not change.
func captureLoop(ctx context.Context, stdout io.Writer, v *view) {
	var lastErr string // logged once until capture recovers or fails differently
	lastDesk := int32(-1)
	var mons []image.Rectangle
	var area image.Rectangle
	var prev, cur *image.RGBA
	ticker := time.NewTicker(frameInterval)
	defer ticker.Stop()
	write := func(b []byte) bool {
		_, err := stdout.Write(b)
		return err == nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		img, err := captureScreen()
		if d := currentDesktop(); d >= 0 && d != lastDesk {
			lastDesk = d
			if !write(screensession.EncodeDesktop(byte(d))) { // #nosec G115 -- a desktop kind
				return
			}
		}
		if err != nil {
			if msg := err.Error(); msg != lastErr {
				lastErr = msg
				log.Printf("screenhelper: capture: %v", err)
			}
			continue
		}
		lastErr = ""
		full := v.refresh.Swap(false)
		if m := monitorRects(); full || !slices.Equal(m, mons) {
			mons = m
			rects := make([]screensession.Rect, len(m))
			for i, r := range m {
				rects[i] = screensession.Rect{X: int32(r.Min.X), Y: int32(r.Min.Y), Width: int32(r.Dx()), Height: int32(r.Dy())} // #nosec G115 -- screen coordinates
			}
			if !write(screensession.EncodeMonitors(rects)) {
				return
			}
		}
		a := img.Rect
		if i := int(v.monitor.Load()); i != screensession.AllMonitors && i < len(mons) {
			if r := mons[i].Intersect(img.Rect); !r.Empty() {
				a = r
			}
		}
		if full || a != area {
			area, prev = a, nil
			v.offX.Store(int32(a.Min.X))                                          // #nosec G115 -- screen coordinates
			v.offY.Store(int32(a.Min.Y))                                          // #nosec G115 -- screen coordinates
			if !write(screensession.EncodeSize(uint32(a.Dx()), uint32(a.Dy()))) { // #nosec G115 -- screen dimensions
				return
			}
		}
		cur = cropCopy(cur, img, a)
		for _, r := range changedStrips(prev, cur) {
			var jpegBuf bytes.Buffer
			if err := jpeg.Encode(&jpegBuf, cur.SubImage(r), &jpeg.Options{Quality: jpegQuality}); err != nil {
				log.Printf("screenhelper: encode: %v", err)
				continue
			}
			if !write(screensession.EncodeTile(uint32(r.Min.X), uint32(r.Min.Y), jpegBuf.Bytes())) { // #nosec G115 -- within the image
				return
			}
		}
		prev, cur = cur, prev
	}
}
