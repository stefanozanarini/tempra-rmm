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
)

// runScreen serves a remote-control session for a signed job: the
// screenhelper process, launched as LocalSystem in the console session (so
// it works with nobody signed in, on the lock screen and on UAC prompts),
// connected to the console over the same Shell stream the interactive
// shell uses, until the operator closes it, the session time is over or it
// is idle. The agent pumps the bytes unchanged between the process and the
// stream (internal/screensession is spoken by the helper and the console
// web handler); it only watches the console's input for Ctrl+Alt+Del,
// which a service alone may press.
func (e *Executor) runScreen(job *openrmmv1.Job, send func(*openrmmv1.JobUpdate), log *slog.Logger) *openrmmv1.JobUpdate {
	var p struct {
		Minutes int `json:"minutes"`
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
	proc, err := usersession.StartSystem([]string{exe, "screenhelper"}, nil, workDir)
	if err != nil {
		return fail(job, "start remote control: %v", err)
	}
	defer proc.Close()

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
	go func() {
		sc := bufio.NewScanner(proc.Stderr())
		for sc.Scan() {
			log.Warn("screenhelper", "msg", sc.Text())
		}
	}()

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
	// Screen frames to the console.
	go func() {
		buf := make([]byte, screenChunk)
		for {
			n, err := proc.Read(buf)
			if n > 0 {
				bytesOut.Add(int64(n))
				if sendFrame(&openrmmv1.ShellFrame{Data: append([]byte(nil), buf[:n]...)}) != nil {
					end("disconnected")
					return
				}
			}
			if err != nil {
				end("exited")
				return
			}
		}
	}()
	idle := time.AfterFunc(screenIdle, func() { end("idle") })
	defer idle.Stop()
	// Input events from the console.
	go func() {
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
			if d := f.GetData(); len(d) > 0 {
				idle.Reset(screenIdle)
				bytesIn.Add(int64(len(d)))
				if frames, err := dec.Feed(d); err == nil {
					for _, fr := range frames {
						if fr.Kind != screensession.SAS {
							continue
						}
						msg := "Ctrl+Alt+Del sent"
						if err := sendSAS(); err != nil {
							msg = "Ctrl+Alt+Del: " + err.Error()
						}
						log.Info("remote control", "sas", msg)
						send(&openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_RUNNING, Message: msg})
					}
				}
				if _, err := proc.Write(d); err != nil {
					end("exited")
					return
				}
			}
		}
	}()
	<-ctx.Done()
	proc.Close()
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
