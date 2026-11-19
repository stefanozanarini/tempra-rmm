package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
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

// Text pasted by the operator reaches the agent as a Clip frame, only for
// agents that can decode one, and the audit log records its length only.
func TestScreenClipboard(t *testing.T) {
	broker := &fakeBroker{recv: make(chan *openrmmv1.ShellFrame, 4)}
	e := startConsole(t, func(cfg *web.Config, _ *signer.Server, _ string) { cfg.Shell = broker })
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "screen"))
	c, csrf := e.login(t, admin)

	session := func(version string) (*websocket.Conn, string) {
		id := ids.NewUUID()
		e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: id, Status: store.AgentActive, CertFingerprint: id,
			Host:         store.HostInfo{Hostname: "PC-" + version, OS: "windows", Arch: "amd64", OSFamily: "client", AgentVersion: version},
			CertNotAfter: time.Now().Add(time.Hour)})
		code, body, final := post(t, c, e.console.URL+"/agents/"+id+"/screen", url.Values{"csrf": {csrf}, "minutes": {"15"}})
		if code != 200 || !strings.HasPrefix(final.Path, "/screen/") {
			t.Fatalf("open screen: %d at %s: %s", code, final, body)
		}
		if strings.Contains(body, `data-clipboard="1"`) != (version == "1.2.4") {
			t.Fatalf("clipboard marker for %s: %s", version, body)
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
		return ws, strings.TrimPrefix(final.Path, "/screen/")
	}

	// An agent too old to decode it never gets the pasted text.
	ws, _ := session("1.2.3")
	websocket.Message.Send(ws, `{"t":"clip","text":"segreto"}`)
	websocket.Message.Send(ws, `{"t":"key","key":86,"down":true}`)
	key := screensession.EncodeKey(86, true)
	waitFor(t, func() bool { return bytes.Contains(broker.data(), key) })
	if bytes.Contains(broker.data(), []byte("segreto")) {
		t.Fatal("clipboard sent to an agent that cannot decode it")
	}
	ws.Close()

	ws, jobID := session("1.2.4")
	defer ws.Close()
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
