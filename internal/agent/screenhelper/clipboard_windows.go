//go:build windows

package screenhelper

// The shared clipboard: text only (CF_UNICODETEXT). The clipboard belongs
// to the window station (WinSta0), not to a desktop, so it is the same on
// the user's desktop, the sign-in screen and a UAC prompt, and any thread
// of the helper may use it. It is opened with no owner window, as most
// clipboard libraries do: the helper has no message loop to answer the
// clipboard messages an owner would receive.

import (
	"errors"
	"runtime"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procEmptyClipboard             = user32.NewProc("EmptyClipboard")
	procGetClipboardData           = user32.NewProc("GetClipboardData")
	procSetClipboardData           = user32.NewProc("SetClipboardData")
	procGetClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")

	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalFree   = kernel32.NewProc("GlobalFree")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
	procGlobalSize   = kernel32.NewProc("GlobalSize")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

var errNoText = errors.New("no text on the clipboard")

// clipboardSeq changes whenever the clipboard content does.
func clipboardSeq() uint32 {
	n, _, _ := procGetClipboardSequenceNumber.Call()
	return uint32(n)
}

// withClipboard opens the clipboard, retrying while another program holds
// it, runs fn and closes it, all on one OS thread.
func withClipboard(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var err error
	for i := 0; i < 20; i++ {
		var ok uintptr
		ok, _, err = procOpenClipboard.Call(0)
		if ok != 0 {
			defer procCloseClipboard.Call()
			return fn()
		}
		time.Sleep(25 * time.Millisecond)
	}
	return err
}

// readClipboard returns the clipboard text, at most max UTF-16 code units.
func readClipboard(max int) (string, error) {
	var out string
	err := withClipboard(func() error {
		h, _, _ := procGetClipboardData.Call(cfUnicodeText)
		if h == 0 {
			return errNoText
		}
		p, _, err := procGlobalLock.Call(h)
		if p == 0 {
			return err
		}
		defer procGlobalUnlock.Call(h)
		size, _, _ := procGlobalSize.Call(h)
		n := int(size / 2)
		units := unsafe.Slice(globalPtr(p), n)
		for i, u := range units {
			if u == 0 {
				n = i
				break
			}
		}
		if n > max {
			return errTooLarge
		}
		out = string(utf16.Decode(units[:n]))
		return nil
	})
	return out, err
}

var errTooLarge = errors.New("clipboard text too large")

// writeClipboard replaces the clipboard content with text.
func writeClipboard(text string) error {
	units := append(utf16.Encode([]rune(text)), 0)
	return withClipboard(func() error {
		if r, _, err := procEmptyClipboard.Call(); r == 0 {
			return err
		}
		size := uintptr(len(units) * 2)
		h, _, err := procGlobalAlloc.Call(gmemMoveable, size)
		if h == 0 {
			return err
		}
		p, _, err := procGlobalLock.Call(h)
		if p == 0 {
			procGlobalFree.Call(h)
			return err
		}
		copy(unsafe.Slice(globalPtr(p), len(units)), units)
		procGlobalUnlock.Call(h)
		// On success the system owns the memory.
		if r, _, err := procSetClipboardData.Call(cfUnicodeText, h); r == 0 {
			procGlobalFree.Call(h)
			return err
		}
		return nil
	})
}

// globalPtr turns the address GlobalLock returns into a pointer. The
// memory is the system's, not Go's: the conversion through a variable
// keeps go vet's unsafe.Pointer check, meant for Go memory, quiet.
func globalPtr(addr uintptr) *uint16 {
	return *(**uint16)(unsafe.Pointer(&addr)) // #nosec G103 -- GlobalLock'd memory, locked while used
}
