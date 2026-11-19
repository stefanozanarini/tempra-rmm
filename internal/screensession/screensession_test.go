package screensession

import (
	"bytes"
	"testing"
)

// feedByte feeds every encoded message one byte at a time, the worst case
// for a stream that can split anywhere, and returns every decoded frame
// in order.
func feedByte(t *testing.T, wire []byte) []Frame {
	t.Helper()
	var dec Decoder
	var out []Frame
	for _, b := range wire {
		frames, err := dec.Feed([]byte{b})
		if err != nil {
			t.Fatalf("Feed: %v", err)
		}
		out = append(out, frames...)
	}
	return out
}

func TestRoundTripByteAtATime(t *testing.T) {
	var wire []byte
	wire = append(wire, EncodeSize(1920, 1080)...)
	wire = append(wire, EncodeImage([]byte{1, 2, 3})...)
	wire = append(wire, EncodeMove(-5, 1200)...)
	wire = append(wire, EncodeButton(ButtonRight, true)...)
	wire = append(wire, EncodeWheel(-120)...)
	wire = append(wire, EncodeKey(0x41, false)...)
	wire = append(wire, EncodeSAS()...)
	wire = append(wire, EncodeDesktop(DesktopWinlogon)...)

	frames := feedByte(t, wire)
	if len(frames) != 8 {
		t.Fatalf("got %d frames, want 8", len(frames))
	}
	if frames[0].Kind != Size || frames[0].Width != 1920 || frames[0].Height != 1080 {
		t.Errorf("size frame: %+v", frames[0])
	}
	if frames[1].Kind != Image || !bytes.Equal(frames[1].Image, []byte{1, 2, 3}) {
		t.Errorf("image frame: %+v", frames[1])
	}
	if frames[2].Kind != Move || frames[2].X != -5 || frames[2].Y != 1200 {
		t.Errorf("move frame: %+v", frames[2])
	}
	if frames[3].Kind != Button || frames[3].Button != ButtonRight || !frames[3].Down {
		t.Errorf("button frame: %+v", frames[3])
	}
	if frames[4].Kind != Wheel || frames[4].Wheel != -120 {
		t.Errorf("wheel frame: %+v", frames[4])
	}
	if frames[5].Kind != Key || frames[5].Key != 0x41 || frames[5].Down {
		t.Errorf("key frame: %+v", frames[5])
	}
	if frames[6].Kind != SAS {
		t.Errorf("SAS frame: %+v", frames[6])
	}
	if frames[7].Kind != Desk || frames[7].Desktop != DesktopWinlogon {
		t.Errorf("desktop frame: %+v", frames[7])
	}
}

func TestFeedWholeAndMultipleFramesAtOnce(t *testing.T) {
	var dec Decoder
	wire := append(EncodeButton(ButtonLeft, true), EncodeButton(ButtonLeft, false)...)
	frames, err := dec.Feed(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 || !frames[0].Down || frames[1].Down {
		t.Fatalf("frames = %+v", frames)
	}
}

func TestImageTooLarge(t *testing.T) {
	var dec Decoder
	hdr := []byte{Image, 0xff, 0xff, 0xff, 0xff} // declares ~4GB
	if _, err := dec.Feed(hdr); err == nil {
		t.Fatal("expected an error for an oversized frame")
	}
}

func TestUnknownKind(t *testing.T) {
	var dec Decoder
	if _, err := dec.Feed([]byte{'?'}); err == nil {
		t.Fatal("expected an error for an unknown frame kind")
	}
}

func TestClipboardFrames(t *testing.T) {
	text := []byte("città · 東京")
	var wire []byte
	wire = append(wire, EncodePolicy(true)...)
	wire = append(wire, EncodeClipboard(text)...)
	wire = append(wire, EncodeClipboard(nil)...)
	frames := feedByte(t, wire)
	if len(frames) != 3 || frames[0].Kind != Policy || !frames[0].Shared {
		t.Fatalf("frames: %+v", frames)
	}
	if frames[1].Kind != Clip || string(frames[1].Text) != string(text) || frames[2].Kind != Clip || len(frames[2].Text) != 0 {
		t.Fatalf("clipboard frames: %+v", frames)
	}
	var dec Decoder
	big := EncodeClipboard(make([]byte, MaxClipboardSize+1))
	if _, err := dec.Feed(big[:5]); err == nil {
		t.Fatal("oversized clipboard accepted")
	}
}

func TestMonitorAndTileFrames(t *testing.T) {
	mons := []Rect{{0, 0, 1920, 1080}, {-1280, 100, 1280, 1024}}
	var wire []byte
	wire = append(wire, EncodeMonitors(mons)...)
	wire = append(wire, EncodeTile(64, 128, []byte{9, 8, 7})...)
	wire = append(wire, EncodeView(1)...)
	wire = append(wire, EncodeView(AllMonitors)...)
	wire = append(wire, EncodeRefresh()...)
	frames := feedByte(t, wire)
	if len(frames) != 5 {
		t.Fatalf("got %d frames", len(frames))
	}
	if frames[0].Kind != Monitors || len(frames[0].Rects) != 2 || frames[0].Rects[1] != mons[1] {
		t.Errorf("monitors frame: %+v", frames[0])
	}
	if frames[1].Kind != Tile || frames[1].X != 64 || frames[1].Y != 128 || !bytes.Equal(frames[1].Image, []byte{9, 8, 7}) {
		t.Errorf("tile frame: %+v", frames[1])
	}
	if frames[2].Kind != View || frames[2].Monitor != 1 || frames[3].Monitor != AllMonitors || frames[4].Kind != Refresh {
		t.Errorf("view/refresh frames: %+v", frames[2:])
	}
	var dec Decoder
	if _, err := dec.Feed([]byte{Monitors, MaxMonitors + 1}); err == nil {
		t.Fatal("too many monitors accepted")
	}
}

func TestFramerCutsAtFrameBoundaries(t *testing.T) {
	var whole []byte
	for _, m := range [][]byte{
		EncodePolicy(true),
		EncodeMonitors([]Rect{{0, 0, 1920, 1080}, {1920, 0, 1280, 1024}}),
		EncodeSize(1920, 1080),
		EncodeTile(64, 128, bytes.Repeat([]byte{7}, 300)),
		EncodeClipboard([]byte("ciao")),
		EncodeDesktop(DesktopWinlogon),
		EncodeImage([]byte{1, 2, 3}),
	} {
		whole = append(whole, m...)
	}
	cut := EncodeTile(0, 0, bytes.Repeat([]byte{9}, 100))
	stream := append(append([]byte(nil), whole...), cut[:40]...)

	for _, chunk := range []int{1, 3, 7, 64, len(stream)} {
		var f Framer
		var got []byte
		for i := 0; i < len(stream); i += chunk {
			out, err := f.Complete(stream[i:min(i+chunk, len(stream))])
			if err != nil {
				t.Fatalf("chunk %d: %v", chunk, err)
			}
			got = append(got, out...)
		}
		if !bytes.Equal(got, whole) {
			t.Fatalf("chunk %d: got %d bytes, want the %d of the whole frames", chunk, len(got), len(whole))
		}
		// A new helper's stream follows: the partial frame is dropped.
		f.Reset()
		out, err := f.Complete(EncodeSize(800, 600))
		if err != nil || !bytes.Equal(out, EncodeSize(800, 600)) {
			t.Fatalf("chunk %d: after reset got %x, %v", chunk, out, err)
		}
	}
}

func TestFramerRejectsGarbage(t *testing.T) {
	var f Framer
	if _, err := f.Complete([]byte{'?', 1, 2}); err == nil {
		t.Fatal("unknown kind accepted")
	}
	f = Framer{}
	if _, err := f.Complete([]byte{Tile, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("oversized tile accepted")
	}
}

func TestUnicodeAndFileFrames(t *testing.T) {
	wire := append(EncodeUnicode('è'), EncodeFile(FilePutData, []byte("abc"))...)
	wire = append(wire, EncodeFile(FilePutEnd, nil)...)
	frames := feedByte(t, wire)
	if len(frames) != 3 || frames[0].Kind != Unicode || frames[0].Rune != 'è' {
		t.Fatalf("frames = %+v", frames)
	}
	if frames[1].Kind != File || frames[1].Op != FilePutData || string(frames[1].Data) != "abc" {
		t.Fatalf("file frame = %+v", frames[1])
	}
	if frames[2].Op != FilePutEnd || len(frames[2].Data) != 0 {
		t.Fatalf("end frame = %+v", frames[2])
	}
	if parts := Split(wire); len(parts) != 3 || !bytes.Equal(parts[0], EncodeUnicode('è')) {
		t.Fatalf("split = %x", parts)
	}
	var dec Decoder
	if _, err := dec.Feed([]byte{File, 0, 0, 0, 0}); err == nil {
		t.Fatal("empty file frame accepted")
	}
}
