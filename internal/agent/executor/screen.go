package executor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/agent/secfile"
	"github.com/stefanozanarini/tempra-rmm/internal/agent/usersession"
	"github.com/stefanozanarini/tempra-rmm/internal/screensession"
)

const (
	screenDefault = 30 * time.Minute
	screenMax     = 60 * time.Minute
	// screenIdle ends a session with no input at all (the operator is
	// still watching if frames keep flowing, but nobody is controlling
	// anything, so an idle session is probably an abandoned tab).
	screenIdle  = 20 * time.Minute
	screenChunk = 64 << 10
	// screenRestarts bounds how many times a session follows the console
	// to another session, and screenSwitchWait how long it waits for the
	// console to be attached to one once the helper is gone.
	screenRestarts   = 5
	screenSwitchWait = 20 * time.Second
)

// runScreen serves a remote-control session for a signed job: the
// screenhelper process, launched as LocalSystem in the console session (so
// it works with nobody signed in, on the lock screen and on UAC prompts),
// connected to the console over the same Shell stream the interactive
// shell uses, until the operator closes it, the session time is over or it
// is idle. The agent pumps the bytes unchanged between the process and the
// stream (internal/screensession is spoken by the helper and the console
// web handler); it only watches the console's input for Ctrl+Alt+Del,
// which a service alone may press, and for the monitor shown.
//
// Signing in at the console can attach it to another session (on a server,
// the user's disconnected one) and end the session the helper ran in.
// The agent then starts a helper in the new console session and goes on
// with the same stream: it forwards whole frames only, so the new helper's
// stream follows cleanly however the old one was cut, and the new helper
// sends the screen anew.
func (e *Executor) runScreen(job *openrmmv1.Job, send func(*openrmmv1.JobUpdate), log *slog.Logger) *openrmmv1.JobUpdate {
	var p struct {
		Minutes  int   `json:"minutes"`
		MaxBytes int64 `json:"max_bytes"`
	}
	_ = json.Unmarshal(job.GetParamsJson(), &p)
	limit := screenDefault
	if p.Minutes > 0 {
		limit = min(time.Duration(p.Minutes)*time.Minute, screenMax)
	}
	e.mu.Lock()
	sess := e.session
	e.mu.Unlock()
	if sess == nil {
		return fail(job, "not connected to the console")
	}
	workDir := filepath.Join(e.work, job.GetJobId())
	if err := secfile.EnsureDir(workDir); err != nil {
		return fail(job, "work directory: %v", err)
	}
	defer os.RemoveAll(workDir)

	exe, err := os.Executable()
	if err != nil {
		return fail(job, "locate agent executable: %v", err)
	}
	args := []string{exe, "screenhelper"}
	if e.cfg.RemoteClipboardAllowed() {
		args = append(args, "-clipboard")
	}
	proc, err := usersession.StartSystem(args, nil, workDir)
	if err != nil {
		return fail(job, "start remote control: %v", err)
	}
	// The helper serving the session, replaced when the console moves to
	// another session.
	var procMu sync.Mutex
	procDone := false
	current := func() *usersession.Process {
		procMu.Lock()
		defer procMu.Unlock()
		return proc
	}
	closeProc := func() {
		procMu.Lock()
		defer procMu.Unlock()
		procDone = true
		proc.Close()
	}
	defer closeProc()

	ctx, cancel := context.WithTimeout(e.ctx, limit)
	defer cancel()
	stream, err := sess.OpenShell(ctx)
	if err != nil {
		return fail(job, "shell stream: %v", err)
	}
	var sendMu sync.Mutex
	sendFrame := func(f *openrmmv1.ShellFrame) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(f)
	}
	if err := sendFrame(&openrmmv1.ShellFrame{JobId: job.GetJobId()}); err != nil {
		return fail(job, "shell stream: %v", err)
	}
	started := time.Now()
	send(&openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_RUNNING, Message: "remote control session open"})
	log.Info("remote control open", "limit", limit)

	// The helper's own diagnostics, kept off the stdout protocol stream.
	logStderr := func(p *usersession.Process) {
		sc := bufio.NewScanner(p.Stderr())
		for sc.Scan() {
			log.Warn("screenhelper", "msg", sc.Text())
		}
	}
	go logStderr(proc)

	var bytesIn, bytesOut atomic.Int64
	ended := "timeout"
	var endMu sync.Mutex
	end := func(why string) {
		endMu.Lock()
		if ended == "timeout" {
			ended = why
		}
		endMu.Unlock()
		cancel()
	}
	// The last monitor choice, given again to a new helper.
	var view atomic.Pointer[[]byte]
	files := &screenFiles{maxBytes: screenFileMax, log: log,
		desktop: func() (string, error) { return usersession.DesktopFolder(current().Session()) },
		send:    func(b []byte) error { return sendFrame(&openrmmv1.ShellFrame{Data: b}) },
		notify: func(msg string) {
			send(&openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_RUNNING, Message: msg})
		}}
	if p.MaxBytes > 0 {
		files.maxBytes = p.MaxBytes
	}
	defer files.close()
	// Screen frames to the console.
	go func() {
		var framer screensession.Framer
		buf := make([]byte, screenChunk)
		p := proc
		for restarts := 0; ; {
			n, err := p.Read(buf)
			if n > 0 {
				bytesOut.Add(int64(n))
				data, ferr := framer.Complete(buf[:n])
				if ferr != nil {
					log.Warn("remote control", "error", ferr)
					end("exited")
					return
				}
				if len(data) > 0 && sendFrame(&openrmmv1.ShellFrame{Data: data}) != nil {
					end("disconnected")
					return
				}
			}
			if err == nil {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			sid, ok := waitConsoleChange(ctx, p.Session())
			if !ok || restarts == screenRestarts {
				end("exited")
				return
			}
			next, err := usersession.StartSystem(args, nil, workDir)
			if err != nil {
				log.Warn("remote control: restart in the new console session", "session", sid, "error", err)
				end("exited")
				return
			}
			restarts++
			framer.Reset()
			procMu.Lock()
			if procDone {
				procMu.Unlock()
				next.Close()
				return
			}
			proc = next
			procMu.Unlock()
			p.Close()
			p = next
			go logStderr(p)
			if v := view.Load(); v != nil {
				_, _ = p.Write(*v)
			}
			log.Info("remote control: console moved to another session, helper restarted", "session", sid)
			send(&openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_RUNNING, Message: "console session changed: remote control resumed"})
		}
	}()
	idle := time.AfterFunc(screenIdle, func() { end("idle") })
	defer idle.Stop()
	// Input events from the console, cut at frame boundaries: file
	// transfer frames are the agent's, the rest goes to the helper.
	go func() {
		var framer screensession.Framer
		var dec screensession.Decoder
		for {
			f, err := stream.Recv()
			if err != nil {
				end("disconnected")
				return
			}
			if f.GetClose() {
				end("closed")
				return
			}
			d := f.GetData()
			if len(d) == 0 {
				continue
			}
			idle.Reset(screenIdle)
			bytesIn.Add(int64(len(d)))
			whole, err := framer.Complete(d)
			if err != nil {
				log.Warn("remote control", "error", err)
				end("protocol error")
				return
			}
			frames, err := dec.Feed(whole)
			parts := screensession.Split(whole)
			if err != nil || len(frames) != len(parts) {
				end("protocol error")
				return
			}
			var fwd []byte
			for i, fr := range frames {
				switch fr.Kind {
				case screensession.File:
					files.handle(ctx, fr)
					continue
				case screensession.View:
					v := screensession.EncodeView(fr.Monitor)
					view.Store(&v)
				case screensession.SAS:
					msg := "Ctrl+Alt+Del sent"
					if err := sendSAS(); err != nil {
						msg = "Ctrl+Alt+Del: " + err.Error()
					}
					log.Info("remote control", "sas", msg)
					send(&openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_RUNNING, Message: msg})
				}
				fwd = append(fwd, parts[i]...)
			}
			// Input written while a helper is being replaced is lost:
			// the screen output decides whether the session goes on.
			if len(fwd) > 0 {
				_, _ = current().Write(fwd)
			}
		}
	}()
	<-ctx.Done()
	closeProc()
	endMu.Lock()
	why := ended
	endMu.Unlock()
	_ = sendFrame(&openrmmv1.ShellFrame{Close: true})
	_ = stream.CloseSend()
	if errors.Is(e.ctx.Err(), context.Canceled) {
		why = "agent stopping"
	}
	log.Info("remote control closed", "ended", why, "duration", time.Since(started).Round(time.Second))
	res, _ := json.Marshal(map[string]any{"ended": why, "duration_seconds": int(time.Since(started).Seconds()),
		"bytes_in": bytesIn.Load(), "bytes_out": bytesOut.Load()})
	return &openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_SUCCEEDED, ResultJson: res, ProgressPercent: 100}
}

// waitConsoleChange waits for the console to be attached to a session
// other than old, and returns it; false when it stays on old (the helper
// ended for another reason) or the session ends first.
func waitConsoleChange(ctx context.Context, old uint32) (uint32, bool) {
	deadline := time.Now().Add(screenSwitchWait)
	for {
		if id, ok := usersession.ConsoleSession(); ok && id != old {
			return id, true
		}
		if time.Now().After(deadline) {
			return 0, false
		}
		select {
		case <-ctx.Done():
			return 0, false
		case <-time.After(250 * time.Millisecond):
		}
	}
}
