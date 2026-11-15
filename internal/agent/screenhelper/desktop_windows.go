//go:build windows

package screenhelper

// The desktop thread: one locked OS thread on which both capture and input
// injection run, and which follows the console session's input desktop.
// The helper runs as LocalSystem in the console session (see
// usersession.StartSystem), so it can move to the sign-in and lock screen
// (Winlogon) and to the secure desktop of UAC prompts, not only the user's
// Default desktop. A thread captures and injects only on its own desktop:
// DXGI duplication, GDI and SendInput all act on the calling thread's
// desktop, hence a single thread that moves wherever the console is.

import (
	"image"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"

	"github.com/stefanozanarini/tempra-rmm/internal/screensession"
)

// genericAll opens the input desktop for capture and SendInput alike.
const genericAll = 0x10000000

var (
	desktopOnce sync.Once
	desktopWork chan func()
	// shownDesktop is the screensession desktop kind the thread is on, -1
	// until it has reached the input desktop once.
	shownDesktop atomic.Int32

	// Owned by the desktop thread.
	capState captureState
	follower desktopFollower
)

// onDesktopThread queues fn to run on the desktop thread, in order.
func onDesktopThread(fn func()) {
	desktopOnce.Do(func() {
		shownDesktop.Store(-1)
		desktopWork = make(chan func(), 64)
		go desktopThread(desktopWork)
	})
	desktopWork <- fn
}

func desktopThread(work <-chan func()) {
	runtime.LockOSThread() // never unlocked: the thread lives as long as the helper
	var sid uint32
	_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid)
	log.Printf("screenhelper: session %d, thread desktop %s, input desktop %s", sid, threadDesktopName(), inputDesktopName())
	for fn := range work {
		fn()
	}
}

type captureResult struct {
	img *image.RGBA
	err error
}

// captureScreen returns one frame of the whole virtual desktop, after
// moving to the input desktop if it changed. The image may be reused by
// the next call, so the caller must be done with it by then.
func captureScreen() (*image.RGBA, error) {
	reply := make(chan captureResult, 1)
	onDesktopThread(func() {
		if follower.follow() {
			capState.reset()
		}
		img, err := capState.capture()
		reply <- captureResult{img, err}
	})
	r := <-reply
	return r.img, r.err
}

// currentDesktop returns the desktop kind shown, or -1 if not known yet.
func currentDesktop() int32 { return shownDesktop.Load() }

// desktopFollower keeps the thread on the input desktop.
type desktopFollower struct {
	h    uintptr // the desktop handle the thread was moved to, 0 at first
	name string
}

// follow moves the thread to the input desktop if it is another one, and
// tells whether it did. A desktop it cannot open (a transient state while
// Windows switches) leaves the thread where it is.
func (d *desktopFollower) follow() bool {
	h, _, _ := procOpenInputDesktop.Call(0, 0, genericAll)
	if h == 0 {
		return false
	}
	name, err := rawDesktopName(h)
	if err != nil || strings.EqualFold(name, d.name) {
		procCloseDesktop.Call(h)
		return false
	}
	if r, _, err := procSetThreadDesktop.Call(h); r == 0 {
		log.Printf("screenhelper: cannot move to desktop %q: %v", name, err)
		procCloseDesktop.Call(h)
		return false
	}
	if d.h != 0 {
		procCloseDesktop.Call(d.h)
	}
	log.Printf("screenhelper: now on desktop %q (was %q)", name, d.name)
	d.h, d.name = h, name
	shownDesktop.Store(int32(desktopKind(name)))
	return true
}

func desktopKind(name string) byte {
	switch strings.ToLower(name) {
	case "default":
		return screensession.DesktopDefault
	case "winlogon":
		return screensession.DesktopWinlogon
	}
	return screensession.DesktopOther
}
