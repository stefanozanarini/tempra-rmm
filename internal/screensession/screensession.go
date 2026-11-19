// Package screensession is the wire protocol of the interactive
// remote-control sessions: an operator watches an agent's screen and
// moves its mouse/keyboard.
//
// A session is a signed job of a module with the screen_session
// capability; its frames travel over the same stream as the interactive
// shell (ShellFrame.data), so the gateway and the relay carry them
// unchanged, exactly as they already do for file sessions. Neither of
// them parses this protocol: only the two real endpoints do — the
// screenhelper process in the user's session, and the console web
// handler. The byte stream may be split at arbitrary points by the
// pipes/gRPC/WebSocket it crosses, so every frame is explicitly
// delimited; nothing here assumes a write on one side arrives whole on
// the other.
//
// From the helper to the console:
//
//	'S' + 4-byte width + 4-byte height (big-endian): the virtual desktop
//	    size, sent once at the start and again if it changes.
//	'F' + 4-byte length + JPEG bytes: one screen frame.
//	'D' + 1 byte: the desktop now shown (DesktopDefault, DesktopWinlogon,
//	    DesktopOther), sent once at the start and again when it changes.
//	'P' + 1 byte (0/1): whether the clipboard is shared in this session
//	    (local policy AllowRemoteClipboard), sent once at the start by
//	    helpers that know the Clip frame; older ones never send it, and the
//	    console then sends them no Clip frame, which they cannot decode.
//	'C' + 4-byte length + UTF-8 text: the remote clipboard changed during
//	    the session (its content from before the session is never sent).
//	'L' + 1-byte count + count x (4-byte x, y, width, height, big-endian,
//	    signed, virtual-desktop pixels): the monitors, the primary first,
//	    sent at the start and again when they change.
//	'T' + 4-byte x + 4-byte y + 4-byte length + JPEG bytes: one changed
//	    part of the screen, at (x, y) of the image last sized by 'S'.
//	    Helpers from agent 1.2.4 send these instead of 'F', and nothing at
//	    all while the screen does not change.
//	'Z' + 4-byte length + op byte + payload: a file transfer message (see
//	    below), from the agent itself, not the helper.
//
// From the console to the helper:
//
//	'M' + 4-byte x + 4-byte y (big-endian, signed, virtual-desktop pixels):
//	    move the mouse.
//	'B' + 1 button byte (0 left, 1 right, 2 middle) + 1 down byte (0/1):
//	    a mouse button.
//	'W' + 4-byte delta (big-endian, signed): the vertical wheel.
//	'K' + 4-byte virtual-key code (big-endian) + 1 down byte (0/1): a key.
//	'A': Ctrl+Alt+Del (the secure attention sequence). The agent itself,
//	    not the helper, acts on it: only a service may generate it.
//	'C' + 4-byte length + UTF-8 text: put this text on the remote
//	    clipboard (the operator is pasting); ignored when the clipboard is
//	    not shared.
//	'V' + 1 byte: show monitor n of the last 'L' list, or every monitor
//	    (AllMonitors). Mouse positions are then relative to that monitor.
//	'R': send the whole screen again, with its 'S' and 'L' (a browser
//	    joined or rejoined the session).
//
//	'U' + 4-byte Unicode code point (big-endian): type this character,
//	    whatever the remote keyboard layout (the operator typed it).
//	'Z' + 4-byte length + op byte + payload: a file transfer message. The
//	    agent itself acts on these and never passes them to the helper.
//
// The console sends 'C', 'V' and 'R' only to agents from 1.2.4, 'U' and
// 'Z' only to agents from 1.2.5: older helpers do not decode them and
// would end the session.
//
// File transfers go one at a time each way. Sending a file to the remote
// computer: FilePut (JSON {"name","size"}), FilePutData chunks, FilePutEnd;
// the agent writes it to the Desktop of the user signed in at the console
// and answers FileResult. Fetching one: FileGet (JSON {"path"}); the agent
// answers FileGetBegin (JSON {"name","size"}), FileGetData chunks and
// FileGetEnd, or FileResult with the error. FileCancel (either way) drops
// the transfer under way. FileResult is JSON {"op","ok","path","error"}.
// From agent 1.2.6, FileList (JSON {"path"}) asks for the content of a
// folder, or with an empty path for the places to start from (drives,
// the signed-in user's Desktop, Documents, Downloads); the agent answers
// FileListing (JSON, see the agent's screenFiles) or FileResult.
//
// The session's end is carried by ShellFrame.close itself, like the
// shell: no close marker is needed in this protocol.
package screensession

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Frame kinds.
const (
	Size     = 'S'
	Image    = 'F'
	Move     = 'M'
	Button   = 'B'
	Wheel    = 'W'
	Key      = 'K'
	SAS      = 'A'
	Desk     = 'D'
	Clip     = 'C'
	Policy   = 'P'
	Monitors = 'L'
	Tile     = 'T'
	View     = 'V'
	Refresh  = 'R'
	Unicode  = 'U'
	File     = 'Z'
)

// File transfer operations, the first byte of a File frame's payload.
const (
	FilePut      = 1
	FilePutData  = 2
	FilePutEnd   = 3
	FileGet      = 4
	FileGetBegin = 5
	FileGetData  = 6
	FileGetEnd   = 7
	FileResult   = 8
	FileCancel   = 9
	FileList     = 10
	FileListing  = 11
)

// FileChunk is the most file data a File frame carries.
const FileChunk = 64 << 10

// AllMonitors in a View frame shows the whole virtual desktop.
const AllMonitors = 0xff

// MaxMonitors bounds a Monitors frame.
const MaxMonitors = 16

// Desktops reported by Desk frames.
const (
	DesktopDefault  = 0 // the user's desktop
	DesktopWinlogon = 1 // sign-in, lock screen
	DesktopOther    = 2 // anything else, e.g. the secure desktop of a UAC prompt
)

// Mouse buttons.
const (
	ButtonLeft = iota
	ButtonRight
	ButtonMiddle
)

// MaxImageSize bounds a single decoded image frame.
const MaxImageSize = 8 << 20

// MaxClipboardSize bounds the text of a Clip frame, in bytes: enough for
// any text an operator pastes, small next to a screen frame.
const MaxClipboardSize = 128 << 10

// Frame is one decoded message.
type Frame struct {
	Kind          byte
	X, Y          int32  // Move, Tile
	Width, Height uint32 // Size
	Button        byte   // Button
	Down          bool   // Button, Key
	Wheel         int32  // Wheel
	Key           uint32 // Key
	Desktop       byte   // Desk
	Shared        bool   // Policy
	Monitor       byte   // View
	Rects         []Rect // Monitors
	Image         []byte // Image, Tile (shares the decoder's buffer: copy before reuse)
	Text          []byte // Clip (shares the decoder's buffer: copy before reuse)
	Rune          rune   // Unicode
	Op            byte   // File
	Data          []byte // File, after the op byte (shares the decoder's buffer: copy before reuse)
}

// Rect is a monitor, in virtual-desktop pixels.
type Rect struct{ X, Y, Width, Height int32 }

// EncodeMonitors returns the wire bytes of a Monitors frame (at most
// MaxMonitors are sent).
func EncodeMonitors(rects []Rect) []byte {
	if len(rects) > MaxMonitors {
		rects = rects[:MaxMonitors]
	}
	b := make([]byte, 2+16*len(rects))
	b[0], b[1] = Monitors, byte(len(rects)) // #nosec G115 -- at most MaxMonitors
	for i, r := range rects {
		o := 2 + 16*i
		for j, v := range []int32{r.X, r.Y, r.Width, r.Height} {
			binary.BigEndian.PutUint32(b[o+4*j:], uint32(v)) // #nosec G115 -- round-trips through the decoder
		}
	}
	return b
}

// EncodeTile returns the wire bytes of a Tile frame.
func EncodeTile(x, y uint32, jpeg []byte) []byte {
	b := make([]byte, 13+len(jpeg))
	b[0] = Tile
	binary.BigEndian.PutUint32(b[1:], x)
	binary.BigEndian.PutUint32(b[5:], y)
	binary.BigEndian.PutUint32(b[9:], uint32(len(jpeg))) // #nosec G115 -- bounded by the encoder
	copy(b[13:], jpeg)
	return b
}

// EncodeView returns the wire bytes of a View frame.
func EncodeView(monitor byte) []byte { return []byte{View, monitor} }

// EncodeRefresh returns the wire bytes of a Refresh frame.
func EncodeRefresh() []byte { return []byte{Refresh} }

// EncodeSize returns the wire bytes of a Size frame.
func EncodeSize(width, height uint32) []byte {
	b := make([]byte, 9)
	b[0] = Size
	binary.BigEndian.PutUint32(b[1:], width)
	binary.BigEndian.PutUint32(b[5:], height)
	return b
}

// EncodeImage returns the wire bytes of an Image frame.
func EncodeImage(jpeg []byte) []byte {
	b := make([]byte, 5+len(jpeg))
	b[0] = Image
	binary.BigEndian.PutUint32(b[1:], uint32(len(jpeg))) // #nosec G115 -- bounded by the encoder
	copy(b[5:], jpeg)
	return b
}

// EncodeClipboard returns the wire bytes of a Clip frame; text must be at
// most MaxClipboardSize bytes.
func EncodeClipboard(text []byte) []byte {
	b := make([]byte, 5+len(text))
	b[0] = Clip
	binary.BigEndian.PutUint32(b[1:], uint32(len(text))) // #nosec G115 -- bounded by MaxClipboardSize
	copy(b[5:], text)
	return b
}

// EncodeUnicode returns the wire bytes of a Unicode frame.
func EncodeUnicode(r rune) []byte {
	b := make([]byte, 5)
	b[0] = Unicode
	binary.BigEndian.PutUint32(b[1:], uint32(r)) // #nosec G115 -- a code point
	return b
}

// EncodeFile returns the wire bytes of a File frame; data must be at most
// FileChunk bytes.
func EncodeFile(op byte, data []byte) []byte {
	b := make([]byte, 6+len(data))
	b[0] = File
	binary.BigEndian.PutUint32(b[1:], uint32(1+len(data))) // #nosec G115 -- bounded by FileChunk
	b[5] = op
	copy(b[6:], data)
	return b
}

// EncodePolicy returns the wire bytes of a Policy frame.
func EncodePolicy(shared bool) []byte { return []byte{Policy, boolByte(shared)} }

// EncodeMove returns the wire bytes of a Move frame.
func EncodeMove(x, y int32) []byte {
	b := make([]byte, 9)
	b[0] = Move
	binary.BigEndian.PutUint32(b[1:], uint32(x)) // #nosec G115 -- round-trips through DecodeMove
	binary.BigEndian.PutUint32(b[5:], uint32(y)) // #nosec G115 -- round-trips through DecodeMove
	return b
}

// EncodeButton returns the wire bytes of a Button frame.
func EncodeButton(button byte, down bool) []byte {
	return []byte{Button, button, boolByte(down)}
}

// EncodeWheel returns the wire bytes of a Wheel frame.
func EncodeWheel(delta int32) []byte {
	b := make([]byte, 5)
	b[0] = Wheel
	binary.BigEndian.PutUint32(b[1:], uint32(delta)) // #nosec G115 -- round-trips through DecodeWheel
	return b
}

// EncodeKey returns the wire bytes of a Key frame.
func EncodeKey(vk uint32, down bool) []byte {
	b := make([]byte, 6)
	b[0] = Key
	binary.BigEndian.PutUint32(b[1:], vk)
	b[5] = boolByte(down)
	return b
}

// EncodeSAS returns the wire bytes of a SAS frame.
func EncodeSAS() []byte { return []byte{SAS} }

// EncodeDesktop returns the wire bytes of a Desk frame.
func EncodeDesktop(d byte) []byte { return []byte{Desk, d} }

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// fixedLen is the payload length (after the tag byte) of every frame kind
// except Image, Clip and Tile, whose length is carried in a 4-byte prefix,
// and Monitors, whose length follows from its count.
var fixedLen = map[byte]int{Size: 8, Move: 8, Button: 2, Wheel: 4, Key: 5, SAS: 0, Desk: 1, Policy: 1, View: 1, Refresh: 0, Unicode: 4}

// maxLen bounds the frames that carry their own length.
var maxLen = map[byte]uint32{Image: MaxImageSize, Clip: MaxClipboardSize, File: 1 + FileChunk}

// Decoder reassembles frames out of a byte stream that may be split at
// arbitrary points. It is not safe for concurrent use.
type Decoder struct {
	buf []byte
}

// ErrFrameTooLarge is returned when an Image or Clip frame's declared
// length exceeds its maximum: the stream is no longer trustworthy and must be
// closed, not resynchronized.
var ErrFrameTooLarge = errors.New("screensession: frame too large")

// Feed appends data and returns every frame now complete. The returned
// frames' Image slices alias Feed's internal buffer and must be copied
// before the next call if kept.
func (d *Decoder) Feed(data []byte) ([]Frame, error) {
	d.buf = append(d.buf, data...)
	var out []Frame
	for {
		if len(d.buf) == 0 {
			return out, nil
		}
		kind := d.buf[0]
		if limit, ok := maxLen[kind]; ok {
			if len(d.buf) < 5 {
				return out, nil
			}
			n := binary.BigEndian.Uint32(d.buf[1:5])
			if n > limit {
				return out, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
			}
			total := 5 + int(n)
			if len(d.buf) < total {
				return out, nil
			}
			f := Frame{Kind: kind}
			switch kind {
			case Image:
				f.Image = d.buf[5:total]
			case File:
				if n == 0 {
					return out, errors.New("screensession: empty file frame")
				}
				f.Op, f.Data = d.buf[5], d.buf[6:total]
			default:
				f.Text = d.buf[5:total]
			}
			out = append(out, f)
			d.buf = d.buf[total:]
			continue
		}
		if kind == Tile {
			if len(d.buf) < 13 {
				return out, nil
			}
			n := binary.BigEndian.Uint32(d.buf[9:13])
			if n > MaxImageSize {
				return out, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
			}
			total := 13 + int(n)
			if len(d.buf) < total {
				return out, nil
			}
			out = append(out, Frame{Kind: Tile, X: int32(binary.BigEndian.Uint32(d.buf[1:5])), Y: int32(binary.BigEndian.Uint32(d.buf[5:9])), // #nosec G115 -- inverse of EncodeTile
				Image: d.buf[13:total]})
			d.buf = d.buf[total:]
			continue
		}
		if kind == Monitors {
			if len(d.buf) < 2 {
				return out, nil
			}
			count := int(d.buf[1])
			if count > MaxMonitors {
				return out, fmt.Errorf("%w: %d monitors", ErrFrameTooLarge, count)
			}
			total := 2 + 16*count
			if len(d.buf) < total {
				return out, nil
			}
			f := Frame{Kind: Monitors, Rects: make([]Rect, count)}
			for i := range f.Rects {
				p := d.buf[2+16*i:]
				f.Rects[i] = Rect{int32(binary.BigEndian.Uint32(p)), int32(binary.BigEndian.Uint32(p[4:])), // #nosec G115 -- inverse of EncodeMonitors
					int32(binary.BigEndian.Uint32(p[8:])), int32(binary.BigEndian.Uint32(p[12:]))} // #nosec G115 -- inverse of EncodeMonitors
			}
			out = append(out, f)
			d.buf = d.buf[total:]
			continue
		}
		n, ok := fixedLen[kind]
		if !ok {
			return out, fmt.Errorf("screensession: unknown frame kind %q", kind)
		}
		if len(d.buf) < 1+n {
			return out, nil
		}
		p := d.buf[1 : 1+n]
		f := Frame{Kind: kind}
		switch kind {
		case Size:
			f.Width, f.Height = binary.BigEndian.Uint32(p), binary.BigEndian.Uint32(p[4:])
		case Move:
			f.X, f.Y = int32(binary.BigEndian.Uint32(p)), int32(binary.BigEndian.Uint32(p[4:])) // #nosec G115 -- inverse of EncodeMove
		case Button:
			f.Button, f.Down = p[0], p[1] != 0
		case Wheel:
			f.Wheel = int32(binary.BigEndian.Uint32(p)) // #nosec G115 -- inverse of EncodeWheel
		case Key:
			f.Key, f.Down = binary.BigEndian.Uint32(p), p[4] != 0
		case Desk:
			f.Desktop = p[0]
		case Policy:
			f.Shared = p[0] != 0
		case View:
			f.Monitor = p[0]
		case Unicode:
			f.Rune = rune(binary.BigEndian.Uint32(p)) // #nosec G115 -- inverse of EncodeUnicode
		}
		out = append(out, f)
		d.buf = d.buf[1+n:]
	}
}

// frameSize returns the length of the frame at the start of b, or 0 when
// b is too short to tell.
func frameSize(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	kind := b[0]
	if limit, ok := maxLen[kind]; ok {
		if len(b) < 5 {
			return 0, nil
		}
		n := binary.BigEndian.Uint32(b[1:5])
		if n > limit {
			return 0, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
		}
		return 5 + int(n), nil
	}
	switch kind {
	case Tile:
		if len(b) < 13 {
			return 0, nil
		}
		n := binary.BigEndian.Uint32(b[9:13])
		if n > MaxImageSize {
			return 0, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
		}
		return 13 + int(n), nil
	case Monitors:
		if len(b) < 2 {
			return 0, nil
		}
		if int(b[1]) > MaxMonitors {
			return 0, fmt.Errorf("%w: %d monitors", ErrFrameTooLarge, b[1])
		}
		return 2 + 16*int(b[1]), nil
	}
	n, ok := fixedLen[kind]
	if !ok {
		return 0, fmt.Errorf("screensession: unknown frame kind %q", kind)
	}
	return 1 + n, nil
}

// Framer cuts a byte stream at frame boundaries without decoding the
// frames, so that a stream from a helper that may die mid-frame can be
// forwarded whole frames only, and another helper's stream can follow it.
type Framer struct {
	buf []byte
}

// Complete appends data and returns the frames now complete, as one new
// slice (nil when none is), holding back a trailing partial frame.
func (f *Framer) Complete(data []byte) ([]byte, error) {
	f.buf = append(f.buf, data...)
	i := 0
	for {
		n, err := frameSize(f.buf[i:])
		if err != nil {
			return nil, err
		}
		if n == 0 || i+n > len(f.buf) {
			break
		}
		i += n
	}
	if i == 0 {
		return nil, nil
	}
	out := append([]byte(nil), f.buf[:i]...)
	f.buf = append(f.buf[:0], f.buf[i:]...)
	return out, nil
}

// Split cuts whole frames, as Complete returns them, into one slice per
// frame (aliasing b).
func Split(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		n, err := frameSize(b)
		if err != nil || n == 0 || n > len(b) {
			break
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}

// Reset drops a partial frame held back, for a new stream to start.
func (f *Framer) Reset() { f.buf = f.buf[:0] }
