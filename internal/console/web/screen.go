package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/net/websocket"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/modules"
	"github.com/stefanozanarini/tempra-rmm/internal/screensession"
)

// minScreenAgent is the first agent version that can run the screenhelper
// in the logged-on user's session (internal/agent/usersession); older
// agents reject the screen module's context "user" outright.
const minScreenAgent = "1.1.4"

// screenAgent tells whether an agent version supports remote control. It
// is only a cheap client-side hint for the context menu: the real check
// is the module lookup in screenModuleFor/handleOpenScreen.
func screenAgent(version string) bool {
	return version != "" && vuln.CompareVersions(version, minScreenAgent) >= 0
}

// minLogonScreenAgent is the first agent version whose remote control runs
// as LocalSystem in the console session: it needs no signed-in user and
// follows the sign-in screen, the lock screen and UAC prompts.
const minLogonScreenAgent = "1.2.0"

// logonScreenAgent tells whether an agent version's remote control works
// without a signed-in user.
func logonScreenAgent(version string) bool {
	return version != "" && vuln.CompareVersions(version, minLogonScreenAgent) >= 0
}

// minScreenV2Agent is the first agent version whose screenhelper speaks
// the second version of internal/screensession: shared clipboard, monitor
// choice, changed parts only. Older ones cannot decode the frames the
// console sends for these (Clip, View, Refresh) and would end the session
// on one.
const minScreenV2Agent = "1.2.4"

// screenV2Agent tells whether an agent version's screenhelper speaks the
// second version of the protocol.
func screenV2Agent(version string) bool {
	return version != "" && vuln.CompareVersions(version, minScreenV2Agent) >= 0
}

// minScreenV3Agent is the first agent version that types characters
// whatever the remote keyboard layout (Unicode frames) and transfers
// files within the session (File frames); older helpers would end the
// session on either.
const minScreenV3Agent = "1.2.5"

// screenV3Agent tells whether an agent version speaks the third version
// of the protocol.
func screenV3Agent(version string) bool {
	return version != "" && vuln.CompareVersions(version, minScreenV3Agent) >= 0
}

// Remote-control sessions: one MFA approval opens a view of one agent's
// screen, with mouse/keyboard control, for a limited time. Served the
// same way as the interactive shell (same Shell stream, same gateway). The
// agent runs as LocalSystem in session 0, with no desktop of its own: it
// runs the screenhelper in the console session (internal/agent/usersession),
// as the signed-in user before agent 1.2.0 (which therefore needs one,
// unlocked), as LocalSystem since.

const (
	screenModule = "screen"
	// screenPickup is how long the agent has to start an approved session.
	screenPickup = 10 * time.Minute
	maxScreenMsg = 256 << 10
)

// isScreenModule tells whether a module version opens remote-control
// sessions.
func (s *Server) isScreenModule(ctx context.Context, id, version string) bool {
	m, err := s.store.GetModule(ctx, id, version)
	if err != nil {
		return false
	}
	man, err := modules.ParseManifest(m.Manifest)
	return err == nil && man.HasCapability(modules.CapScreenSession)
}

// screenModuleFor returns the newest screen module for the agent's platform.
func (s *Server) screenModuleFor(r *http.Request, a store.Agent) (store.Module, bool) {
	latest, err := s.latestModules(r)
	if err != nil {
		return store.Module{}, false
	}
	m, err := s.store.GetModule(r.Context(), screenModule, latest[screenModule])
	if err != nil {
		return store.Module{}, false
	}
	man, err := modules.ParseManifest(m.Manifest)
	if err != nil || !man.HasCapability(modules.CapScreenSession) {
		return store.Module{}, false
	}
	if _, ok := man.Entrypoints[a.Host.OS+"/"+a.Host.Arch]; !ok {
		return store.Module{}, false
	}
	return m, true
}

func (s *Server) handleOpenScreen(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	back := "/agents/" + id
	a, err := s.store.GetAgent(r.Context(), t, id)
	if err != nil || a.Status != store.AgentActive {
		s.flash(w, r, s.T(r, "Solo gli agenti approvati possono ricevere comandi."), back)
		return
	}
	mod, ok := s.screenModuleFor(r, a)
	if !ok || s.shell == nil {
		s.flash(w, r, s.T(r, "Il controllo remoto non è disponibile su questa console."), back)
		return
	}
	minutes, err := strconv.Atoi(r.PostFormValue("minutes"))
	if err != nil || minutes < 5 || minutes > 60 {
		minutes = 30
	}
	set, err := s.store.GetSettings(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// max_bytes bounds the files transferred within the session, as in
	// file sessions.
	params, _ := json.Marshal(map[string]int64{"minutes": int64(minutes), "max_bytes": fileMaxBytes(set)})
	req := &openrmmv1.JobRequest{TenantId: t, AgentId: id, Module: mod.ID, ModuleVersion: mod.Version, ModuleSha256: mod.ManifestSHA256,
		Action: "open", ParamsJson: params, TtlSeconds: int64(screenPickup / time.Second), RequestNonce: jobreq.NewRequestNonce()}
	if err := jobreq.Validate(req); err != nil {
		s.flash(w, r, s.Tf(r, "Richiesta non valida: %v", err), back)
		return
	}
	s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
}

// screenJob returns a screen job that the operator approved and may attach to.
func (s *Server) screenJob(r *http.Request) (store.Job, store.Agent, bool) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		return store.Job{}, store.Agent{}, false
	}
	j, err := s.store.GetJob(r.Context(), t, id)
	op := sessionFrom(r.Context()).data.Operator
	// Only the operator who approved the session may use it.
	if err != nil || j.CreatedBy != "operator:"+op.Username || !s.isScreenModule(r.Context(), j.Module, j.ModuleVersion) {
		return store.Job{}, store.Agent{}, false
	}
	a, err := s.store.GetAgent(r.Context(), t, j.AgentID)
	if err != nil {
		return store.Job{}, store.Agent{}, false
	}
	return j, a, true
}

type screenData struct {
	Job     store.Job
	Agent   store.Agent
	Minutes int
	By      string // approving operator
}

const screenCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"connect-src 'self'; img-src 'self' blob:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func (s *Server) handleScreenPage(w http.ResponseWriter, r *http.Request) {
	j, a, ok := s.screenJob(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// This page draws to a <canvas> with its own small script, served by
	// the console: no third-party script or style. Each frame is decoded
	// from a blob: URL the script creates, which img-src must allow, or the
	// browser drops every frame and the canvas stays black.
	w.Header().Set("Content-Security-Policy", screenCSP)
	var p struct {
		Minutes int `json:"minutes"`
	}
	_ = json.Unmarshal(j.Params, &p)
	s.render(w, r, "screen", s.Tf(r, "Controllo remoto di %s", a.Host.Hostname), screenData{Job: j, Agent: a, Minutes: p.Minutes,
		By: strings.TrimPrefix(j.CreatedBy, "operator:")})
}

// screenMsg is the browser's input events; the server turns them into the
// internal/screensession wire format the agent's screenhelper speaks.
type screenMsg struct {
	T       string `json:"t"` // move, button, wheel, key, char, sas, clip, monitor, fileput, filedata, fileend, fileget, filecancel, close
	X       int32  `json:"x,omitempty"`
	Y       int32  `json:"y,omitempty"`
	Button  byte   `json:"button,omitempty"`
	Down    bool   `json:"down,omitempty"`
	Delta   int32  `json:"delta,omitempty"`
	Key     uint32 `json:"key,omitempty"`
	Text    string `json:"text,omitempty"` // clip
	Monitor int    `json:"monitor"`        // monitor: index, or -1 for all
	Char    string `json:"char,omitempty"` // char: one character
	Name    string `json:"name,omitempty"` // fileput
	Size    int64  `json:"size,omitempty"` // fileput
	Data    []byte `json:"data,omitempty"` // filedata (base64 in JSON)
	Path    string `json:"path,omitempty"` // fileget
}

// handleScreenSocket joins the browser's canvas to the session.
func (s *Server) handleScreenSocket(w http.ResponseWriter, r *http.Request) {
	j, a, ok := s.screenJob(r)
	if !ok || s.shell == nil {
		http.NotFound(w, r)
		return
	}
	sess := sessionFrom(r.Context())
	op := sess.data.Operator
	srv := websocket.Server{
		Handshake: func(_ *websocket.Config, req *http.Request) error {
			// Same-origin only; over a federation link the central console
			// has checked the origin.
			if op.Federated || req.Header.Get("Origin") == s.origin {
				return nil
			}
			return errors.New("origin not allowed")
		},
		Handler: func(ws *websocket.Conn) { s.serveScreen(ws, r, j, a, op) },
	}
	srv.ServeHTTP(w, r)
}

func (s *Server) serveScreen(ws *websocket.Conn, r *http.Request, j store.Job, a store.Agent, op *Operator) {
	defer ws.Close()
	// The server's write timeout does not apply to a session.
	_ = ws.SetDeadline(time.Time{})
	ws.MaxPayloadBytes = maxScreenMsg
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stream, err := s.shell.Attach(ctx)
	if err == nil {
		err = stream.Send(&openrmmv1.ShellFrame{TenantId: j.TenantID, JobId: j.ID})
	}
	if err != nil {
		_ = websocket.Message.Send(ws, s.T(r, "La sessione non è disponibile."))
		return
	}
	s.audit(r.Context(), j.TenantID, op, "screen.attached", j.ID, map[string]any{"agent": a.ID, "hostname": a.Host.Hostname})
	v2 := screenV2Agent(a.Host.AgentVersion)
	v3 := screenV3Agent(a.Host.AgentVersion)
	if v2 {
		// The helper sends only what changes: a browser joining (or
		// rejoining after a reload) needs the whole screen first.
		if err := stream.Send(&openrmmv1.ShellFrame{Data: screensession.EncodeRefresh()}); err != nil {
			_ = websocket.Message.Send(ws, s.T(r, "La sessione non è disponibile."))
			return
		}
	}
	var wsMu sync.Mutex
	sendWS := func(v any) error {
		wsMu.Lock()
		defer wsMu.Unlock()
		return websocket.Message.Send(ws, v)
	}
	// Input events to the agent.
	go func() {
		defer cancel()
		for {
			var raw string
			if err := websocket.Message.Receive(ws, &raw); err != nil {
				return
			}
			var m screenMsg
			if json.Unmarshal([]byte(raw), &m) != nil {
				continue
			}
			f := &openrmmv1.ShellFrame{}
			switch m.T {
			case "move":
				f.Data = screensession.EncodeMove(m.X, m.Y)
			case "button":
				f.Data = screensession.EncodeButton(m.Button, m.Down)
			case "wheel":
				f.Data = screensession.EncodeWheel(m.Delta)
			case "key":
				f.Data = screensession.EncodeKey(m.Key, m.Down)
			case "char":
				rs := []rune(m.Char)
				if !v3 || len(rs) != 1 || rs[0] < ' ' || rs[0] == utf8.RuneError {
					continue
				}
				f.Data = screensession.EncodeUnicode(rs[0])
			case "sas":
				f.Data = screensession.EncodeSAS()
			case "clip":
				// Pasted text for the remote clipboard; the helper ignores
				// it where the local policy does not share the clipboard.
				if !v2 || len(m.Text) > screensession.MaxClipboardSize {
					continue
				}
				f.Data = screensession.EncodeClipboard([]byte(m.Text))
				// The length only: pasted text is often a password.
				s.audit(context.WithoutCancel(r.Context()), j.TenantID, op, "screen.clipboard_pasted", j.ID,
					map[string]any{"agent": a.ID, "characters": utf8.RuneCountInString(m.Text)})
			case "monitor":
				if !v2 || m.Monitor < -1 || m.Monitor >= screensession.MaxMonitors {
					continue
				}
				view := byte(screensession.AllMonitors)
				if m.Monitor >= 0 {
					view = byte(m.Monitor)
				}
				f.Data = screensession.EncodeView(view)
			case "fileput":
				if !v3 || m.Size < 0 || len(m.Name) > 255 {
					continue
				}
				head, _ := json.Marshal(map[string]any{"name": m.Name, "size": m.Size})
				f.Data = screensession.EncodeFile(screensession.FilePut, head)
				s.audit(context.WithoutCancel(r.Context()), j.TenantID, op, "screen.file_sent", j.ID,
					map[string]any{"agent": a.ID, "name": m.Name, "bytes": m.Size})
			case "filedata":
				if !v3 || len(m.Data) > screensession.FileChunk {
					continue
				}
				f.Data = screensession.EncodeFile(screensession.FilePutData, m.Data)
			case "fileend":
				if !v3 {
					continue
				}
				f.Data = screensession.EncodeFile(screensession.FilePutEnd, nil)
			case "fileget":
				if !v3 || m.Path == "" || len(m.Path) > 1024 {
					continue
				}
				req, _ := json.Marshal(map[string]string{"path": m.Path})
				f.Data = screensession.EncodeFile(screensession.FileGet, req)
				s.audit(context.WithoutCancel(r.Context()), j.TenantID, op, "screen.file_fetched", j.ID,
					map[string]any{"agent": a.ID, "path": m.Path})
			case "filecancel":
				if !v3 {
					continue
				}
				f.Data = screensession.EncodeFile(screensession.FileCancel, nil)
			case "close":
				f.Close = true
			default:
				continue
			}
			if stream.Send(f) != nil || f.Close {
				return
			}
		}
	}()
	go s.watchSession(ctx, r, j, sendWS, cancel)
	// Screen frames to the browser: forwarded as opaque bytes, exactly as
	// the agent sent them. Only the two real endpoints (screenhelper and
	// the browser's own script) parse internal/screensession's framing.
	for {
		f, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				_ = sendWS(s.T(r, "La sessione non è disponibile."))
			}
			break
		}
		if len(f.GetData()) > 0 {
			if sendWS(f.GetData()) != nil {
				break
			}
		}
		if f.GetClose() {
			_ = sendWS(s.T(r, "Sessione chiusa."))
			break
		}
	}
	_ = stream.CloseSend()
	s.audit(context.WithoutCancel(r.Context()), j.TenantID, op, "screen.detached", j.ID, map[string]any{"agent": a.ID})
}
