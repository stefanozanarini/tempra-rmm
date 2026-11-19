package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"google.golang.org/grpc"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/signer"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/web"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/screensession"
)

// fakeBroker stands for the gateway's shell broker: it records what the
// console sends to the agent and lets the test play the agent's part.
type fakeBroker struct {
	mu   sync.Mutex
	sent []byte // data frames from the console, concatenated
	recv chan *openrmmv1.ShellFrame
}

func (b *fakeBroker) Attach(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[openrmmv1.ShellFrame, openrmmv1.ShellFrame], error) {
	return &fakeStream{b: b, ctx: ctx}, nil
}

func (b *fakeBroker) data() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.sent...)
}

type fakeStream struct {
	grpc.ClientStream
	b   *fakeBroker
	ctx context.Context
}

func (s *fakeStream) Send(f *openrmmv1.ShellFrame) error {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	s.b.sent = append(s.b.sent, f.GetData()...)
	return nil
}

func (s *fakeStream) Recv() (*openrmmv1.ShellFrame, error) {
	select {
	case f := <-s.b.recv:
		return f, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *fakeStream) CloseSend() error { return nil }

// The frames of the second protocol version (pasted text, monitor choice,
// refresh) reach only agents that can decode them, and the audit log
// records the length of pasted text only.
// openScreen opens a remote-control session on a new agent of the given
// version and joins its WebSocket; it returns the page too.
func openScreen(t *testing.T, e *consoleEnv, c *http.Client, csrf, version string) (*websocket.Conn, string, string) {
	t.Helper()
	id := ids.NewUUID()
	e.store.CreateAgent(context.Background(), store.Agent{TenantID: e.tenant, ID: id, Status: store.AgentActive, CertFingerprint: id,
		Host:         store.HostInfo{Hostname: "PC-" + version, OS: "windows", Arch: "amd64", OSFamily: "client", AgentVersion: version},
		CertNotAfter: time.Now().Add(time.Hour)})
	code, body, final := post(t, c, e.console.URL+"/agents/"+id+"/screen", url.Values{"csrf": {csrf}, "minutes": {"15"}})
	if code != 200 || !strings.HasPrefix(final.Path, "/screen/") {
		t.Fatalf("open screen: %d at %s: %s", code, final, body)
	}
	u, _ := url.Parse(e.console.URL)
	wcfg, _ := websocket.NewConfig("wss://"+u.Host+final.Path+"/ws", e.console.URL)
	wcfg.TlsConfig = &tls.Config{RootCAs: e.console.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	for _, ck := range c.Jar.Cookies(u) {
		wcfg.Header.Add("Cookie", ck.Name+"="+ck.Value)
	}
	ws, err := websocket.DialConfig(wcfg)
	if err != nil {
		t.Fatal(err)
	}
	return ws, strings.TrimPrefix(final.Path, "/screen/"), body
}

func TestScreenProtocolV2(t *testing.T) {
	broker := &fakeBroker{recv: make(chan *openrmmv1.ShellFrame, 4)}
	e := startConsole(t, func(cfg *web.Config, _ *signer.Server, _ string) { cfg.Shell = broker })
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "screen"))
	c, csrf := e.login(t, admin)

	session := func(version string) (*websocket.Conn, string) {
		ws, jobID, body := openScreen(t, e, c, csrf, version)
		if strings.Contains(body, `data-v2="1"`) != (version == "1.2.4") {
			t.Fatalf("protocol marker for %s: %s", version, body)
		}
		return ws, jobID
	}

	// An agent too old to decode them never gets the pasted text, a
	// monitor choice or a refresh request.
	ws, _ := session("1.2.3")
	websocket.Message.Send(ws, `{"t":"clip","text":"segreto"}`)
	websocket.Message.Send(ws, `{"t":"monitor","monitor":1}`)
	websocket.Message.Send(ws, `{"t":"key","key":86,"down":true}`)
	key := screensession.EncodeKey(86, true)
	waitFor(t, func() bool { return bytes.Contains(broker.data(), key) })
	// Only the key went through.
	if d := broker.data(); !bytes.Equal(d, key) {
		t.Fatalf("new frames sent to an agent that cannot decode them: %q", d)
	}
	ws.Close()

	// A newer agent is asked for the whole screen as the browser joins.
	before := len(broker.data())
	ws, jobID := session("1.2.4")
	defer ws.Close()
	waitFor(t, func() bool { return bytes.Contains(broker.data()[before:], screensession.EncodeRefresh()) })
	websocket.Message.Send(ws, `{"t":"monitor","monitor":1}`)
	websocket.Message.Send(ws, `{"t":"monitor","monitor":-1}`)
	waitFor(t, func() bool {
		d := broker.data()[before:]
		return bytes.Contains(d, screensession.EncodeView(1)) && bytes.Contains(d, screensession.EncodeView(screensession.AllMonitors))
	})
	websocket.Message.Send(ws, `{"t":"clip","text":"città"}`)
	want := screensession.EncodeClipboard([]byte("città"))
	waitFor(t, func() bool { return bytes.Contains(broker.data(), want) })
	// Too long: dropped.
	websocket.Message.Send(ws, `{"t":"clip","text":"`+strings.Repeat("x", screensession.MaxClipboardSize+1)+`"}`)

	// Frames from the agent, the remote clipboard included, reach the
	// browser unchanged.
	broker.recv <- &openrmmv1.ShellFrame{Data: screensession.EncodeClipboard([]byte("copiato"))}
	for {
		var b []byte
		ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := websocket.Message.Receive(ws, &b); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(b, screensession.EncodeClipboard([]byte("copiato"))) {
			break
		}
	}

	waitFor(t, func() bool {
		events, _ := e.store.ListAudit(ctx, e.tenant)
		n := 0
		for _, ev := range events {
			if ev.Action == "screen.clipboard_pasted" && ev.Target == jobID {
				if fmt.Sprint(ev.Details["characters"]) != "5" {
					t.Fatalf("audit details = %v", ev.Details)
				}
				n++
			}
		}
		return n == 1
	})
}

func TestScreenProtocolV3(t *testing.T) {
	broker := &fakeBroker{recv: make(chan *openrmmv1.ShellFrame, 4)}
	e := startConsole(t, func(cfg *web.Config, _ *signer.Server, _ string) { cfg.Shell = broker })
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "screen"))
	c, csrf := e.login(t, admin)

	// 1.2.4 gets neither characters nor file transfers.
	ws, _, body := openScreen(t, e, c, csrf, "1.2.4")
	if strings.Contains(body, `data-v3="1"`) || strings.Contains(body, `id="screen-files"`) {
		t.Fatal("file transfer offered to agent 1.2.4")
	}
	websocket.Message.Send(ws, `{"t":"char","char":"è"}`)
	websocket.Message.Send(ws, `{"t":"fileput","name":"a.txt","size":1}`)
	websocket.Message.Send(ws, `{"t":"key","key":13,"down":true}`)
	key := screensession.EncodeKey(13, true)
	waitFor(t, func() bool { return bytes.Contains(broker.data(), key) })
	if d := broker.data(); bytes.Contains(d, []byte{screensession.Unicode}) || bytes.Contains(d, []byte{screensession.File}) {
		t.Fatalf("v3 frames sent to agent 1.2.4: %q", d)
	}
	ws.Close()

	ws, jobID, body := openScreen(t, e, c, csrf, "1.2.5")
	defer ws.Close()
	if !strings.Contains(body, `data-v3="1"`) || !strings.Contains(body, `id="screen-files"`) {
		t.Fatal("no file transfer for agent 1.2.5")
	}
	// The browser's right button (2) is the protocol's ButtonRight (1).
	websocket.Message.Send(ws, `{"t":"button","button":2,"down":true}`)
	websocket.Message.Send(ws, `{"t":"button","button":1,"down":true}`)
	websocket.Message.Send(ws, `{"t":"char","char":"è"}`)
	websocket.Message.Send(ws, `{"t":"char","char":"ab"}`) // not one character: dropped
	websocket.Message.Send(ws, `{"t":"fileput","name":"report.pdf","size":3}`)
	websocket.Message.Send(ws, `{"t":"filedata","data":"YWJj"}`)
	websocket.Message.Send(ws, `{"t":"fileend"}`)
	websocket.Message.Send(ws, `{"t":"fileget","path":"C:\\Windows\\win.ini"}`)
	head, _ := json.Marshal(map[string]any{"name": "report.pdf", "size": 3})
	get, _ := json.Marshal(map[string]string{"path": `C:\Windows\win.ini`})
	want := [][]byte{screensession.EncodeButton(screensession.ButtonRight, true), screensession.EncodeButton(screensession.ButtonMiddle, true),
		screensession.EncodeUnicode('è'), screensession.EncodeFile(screensession.FilePut, head),
		screensession.EncodeFile(screensession.FilePutData, []byte("abc")), screensession.EncodeFile(screensession.FilePutEnd, nil),
		screensession.EncodeFile(screensession.FileGet, get)}
	waitFor(t, func() bool { return bytes.Contains(broker.data(), want[len(want)-1]) })
	d := broker.data()
	for _, w := range want {
		if !bytes.Contains(d, w) {
			t.Fatalf("missing %q in %q", w, d)
		}
	}
	if bytes.Contains(d, screensession.EncodeUnicode('a')) {
		t.Fatal("a two-character message went through")
	}
	// 1.2.5 cannot list folders: no browser, no FileList.
	websocket.Message.Send(ws, `{"t":"filelist","path":"C:\\"}`)
	if strings.Contains(body, `id="screen-file-browse"`) {
		t.Fatal("folder browser offered to agent 1.2.5")
	}
	ws6, _, body6 := openScreen(t, e, c, csrf, "1.2.6")
	defer ws6.Close()
	if !strings.Contains(body6, `id="screen-file-browse"`) || !strings.Contains(body6, `data-browse="1"`) {
		t.Fatal("no folder browser for agent 1.2.6")
	}
	websocket.Message.Send(ws6, `{"t":"filelist","path":""}`)
	list, _ := json.Marshal(map[string]string{"path": ""})
	waitFor(t, func() bool {
		return bytes.Contains(broker.data(), screensession.EncodeFile(screensession.FileList, list))
	})
	if bytes.Contains(broker.data(), screensession.EncodeFile(screensession.FileList, []byte(`{"path":"C:\\"}`))) {
		t.Fatal("FileList sent to agent 1.2.5")
	}
	waitFor(t, func() bool {
		events, _ := e.store.ListAudit(ctx, e.tenant)
		sent, fetched := false, false
		for _, ev := range events {
			if ev.Target != jobID {
				continue
			}
			sent = sent || ev.Action == "screen.file_sent" && ev.Details["name"] == "report.pdf"
			fetched = fetched || ev.Action == "screen.file_fetched" && ev.Details["path"] == `C:\Windows\win.ini`
		}
		return sent && fetched
	})
}
