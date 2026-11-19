//go:build windows

package screenhelper

import (
	"bytes"
	"context"
	"image/jpeg"
	"io"
	"log"
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
	go captureLoop(ctx, out)

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
				if f.Kind == screensession.Clip {
					// Set before the next frame (the operator's Ctrl+V)
					// is injected.
					if shareClipboard {
						pasteText(string(f.Text), &seen)
					}
					continue
				}
				applyInput(f)
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
	}
	if err != nil {
		log.Printf("screenhelper: input: %v", err)
	}
}

func captureLoop(ctx context.Context, stdout io.Writer) {
	var lastW, lastH int
	var lastErr string // logged once until capture recovers or fails differently
	lastDesk := int32(-1)
	ticker := time.NewTicker(frameInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		img, err := captureScreen()
		if d := currentDesktop(); d >= 0 && d != lastDesk {
			lastDesk = d
			if _, err := stdout.Write(screensession.EncodeDesktop(byte(d))); err != nil { // #nosec G115 -- a desktop kind
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
		b := img.Bounds()
		if b.Dx() != lastW || b.Dy() != lastH {
			lastW, lastH = b.Dx(), b.Dy()
			if _, err := stdout.Write(screensession.EncodeSize(uint32(lastW), uint32(lastH))); err != nil { // #nosec G115 -- screen dimensions
				return
			}
		}
		var jpegBuf bytes.Buffer
		if err := jpeg.Encode(&jpegBuf, img, &jpeg.Options{Quality: jpegQuality}); err != nil {
			log.Printf("screenhelper: encode: %v", err)
			continue
		}
		if _, err := stdout.Write(screensession.EncodeImage(jpegBuf.Bytes())); err != nil {
			return
		}
	}
}
