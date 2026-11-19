package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/agent/usersession"
	"github.com/stefanozanarini/tempra-rmm/internal/screensession"
)

// screenFileMax bounds a file sent either way when the job sets no limit.
const screenFileMax = 512 << 20

// screenFiles serves the file transfers of a remote-control session: the
// operator drops a file, which lands on the Desktop of the user signed in
// at the console, or fetches one by its path. One transfer each way at a
// time; the remote-control approval covers them, since the operator
// already controls the computer.
type screenFiles struct {
	maxBytes int64
	desktop  func() (string, error)     // where received files go
	places   func() []usersession.Place // the signed-in user's folders, to start browsing from
	send     func(frame []byte) error
	log      *slog.Logger
	notify   func(msg string) // a line for the job's history

	put     *os.File
	putName string
	putSize int64
	putGot  int64

	mu        sync.Mutex
	getCancel context.CancelFunc
}

// fileResult is the FileResult payload.
type fileResult struct {
	Op    string `json:"op"`
	OK    bool   `json:"ok"`
	Path  string `json:"path,omitempty"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

// fileError is an error with a code the console translates.
type fileError struct{ code, msg string }

func (e *fileError) Error() string { return e.msg }

func (f *screenFiles) result(op string, path string, err error) {
	r := fileResult{Op: op, OK: err == nil, Path: path}
	if err != nil {
		r.Code, r.Error = "io", err.Error()
		var fe *fileError
		if errors.As(err, &fe) {
			r.Code = fe.code
		}
	}
	b, _ := json.Marshal(r)
	_ = f.send(screensession.EncodeFile(screensession.FileResult, b))
}

// handle acts on a File frame from the console; its Data is only valid
// during the call.
func (f *screenFiles) handle(ctx context.Context, fr screensession.Frame) {
	switch fr.Op {
	case screensession.FilePut:
		f.abortPut()
		var p struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		}
		if err := json.Unmarshal(fr.Data, &p); err != nil {
			f.result("put", "", err)
			return
		}
		if err := f.beginPut(p.Name, p.Size); err != nil {
			f.result("put", "", err)
		}
	case screensession.FilePutData:
		if f.put == nil {
			return // after an error: the rest of the file is dropped
		}
		f.putGot += int64(len(fr.Data))
		if f.putGot > f.putSize {
			f.abortPut()
			f.result("put", "", errors.New("more data than announced"))
			return
		}
		if _, err := f.put.Write(fr.Data); err != nil {
			f.abortPut()
			f.result("put", "", err)
		}
	case screensession.FilePutEnd:
		if f.put == nil {
			return
		}
		path, err := f.endPut()
		f.result("put", path, err)
		if err == nil {
			f.log.Info("remote control: file received", "path", path, "bytes", f.putSize)
			f.notify(fmt.Sprintf("file received: %s (%d bytes)", path, f.putSize))
		}
	case screensession.FileGet:
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(fr.Data, &p); err != nil {
			f.result("get", "", err)
			return
		}
		f.startGet(ctx, p.Path)
	case screensession.FileList:
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(fr.Data, &p); err != nil {
			f.result("list", "", err)
			return
		}
		b, err := f.list(p.Path)
		if err != nil {
			f.result("list", p.Path, err)
			return
		}
		_ = f.send(screensession.EncodeFile(screensession.FileListing, b))
	case screensession.FileCancel:
		f.abortPut()
		f.mu.Lock()
		if f.getCancel != nil {
			f.getCancel()
		}
		f.mu.Unlock()
	}
}

// cleanName keeps a file name safe to create on Windows: no folders, no
// reserved characters, no trailing dots or spaces.
func cleanName(name string) (string, bool) {
	name = name[strings.LastIndexAny(name, `/\`)+1:]
	name = strings.TrimRight(strings.TrimSpace(name), ". ")
	if name == "" || len(name) > 200 || strings.ContainsAny(name, `<>:"|?*`) {
		return "", false
	}
	for _, r := range name {
		if r < 32 {
			return "", false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return "", false
	}
	return name, true
}

func (f *screenFiles) beginPut(name string, size int64) error {
	clean, ok := cleanName(name)
	if !ok {
		return &fileError{"bad_name", "invalid file name"}
	}
	if size < 0 || size > f.maxBytes {
		return &fileError{"too_large", fmt.Sprintf("file larger than %d bytes", f.maxBytes)}
	}
	dir, err := f.desktop()
	if err != nil {
		if errors.Is(err, usersession.ErrNoUser) {
			return &fileError{"no_user", "nobody is signed in at the console"}
		}
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tempra-*.part")
	if err != nil {
		return err
	}
	f.put, f.putName, f.putSize, f.putGot = tmp, clean, size, 0
	return nil
}

// endPut gives the received file its name, next to any file already
// called so: "report.pdf", then "report (2).pdf".
func (f *screenFiles) endPut() (string, error) {
	tmp := f.put
	f.put = nil
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	if f.putGot != f.putSize {
		_ = os.Remove(tmp.Name())
		return "", errors.New("file cut short")
	}
	dir := filepath.Dir(tmp.Name())
	ext := filepath.Ext(f.putName)
	stem := strings.TrimSuffix(f.putName, ext)
	for i := 1; i < 1000; i++ {
		name := f.putName
		if i > 1 {
			name = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := os.Rename(tmp.Name(), path); err != nil {
			_ = os.Remove(tmp.Name())
			return "", err
		}
		return path, nil
	}
	_ = os.Remove(tmp.Name())
	return "", errors.New("no free file name")
}

func (f *screenFiles) abortPut() {
	if f.put != nil {
		_ = f.put.Close()
		_ = os.Remove(f.put.Name())
		f.put = nil
	}
}

func (f *screenFiles) startGet(ctx context.Context, path string) {
	f.mu.Lock()
	if f.getCancel != nil {
		f.mu.Unlock()
		f.result("get", path, &fileError{"busy", "another file is being sent"})
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	f.getCancel = cancel
	f.mu.Unlock()
	go func() {
		defer func() {
			f.mu.Lock()
			f.getCancel = nil
			f.mu.Unlock()
			cancel()
		}()
		n, err := f.get(ctx, path)
		if err != nil {
			f.result("get", path, err)
			return
		}
		f.log.Info("remote control: file sent", "path", path, "bytes", n)
		f.notify(fmt.Sprintf("file sent: %s (%d bytes)", path, n))
	}()
}

func (f *screenFiles) get(ctx context.Context, path string) (int64, error) {
	path = strings.Trim(strings.TrimSpace(path), `"`)
	if !filepath.IsAbs(path) {
		return 0, &fileError{"bad_path", "give the full path of the file"}
	}
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, &fileError{"not_found", "file not found"}
	}
	if err != nil {
		return 0, err
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if !st.Mode().IsRegular() {
		return 0, &fileError{"not_file", "not a file"}
	}
	if st.Size() > f.maxBytes {
		return 0, &fileError{"too_large", fmt.Sprintf("file larger than %d bytes", f.maxBytes)}
	}
	head, _ := json.Marshal(map[string]any{"name": filepath.Base(path), "size": st.Size()})
	if err := f.send(screensession.EncodeFile(screensession.FileGetBegin, head)); err != nil {
		return 0, err
	}
	buf := make([]byte, screensession.FileChunk)
	var sent int64
	for {
		if ctx.Err() != nil {
			return sent, ctx.Err()
		}
		n, err := file.Read(buf)
		if n > 0 {
			if err := f.send(screensession.EncodeFile(screensession.FileGetData, buf[:n])); err != nil {
				return sent, err
			}
			sent += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return sent, err
		}
	}
	if sent != st.Size() {
		return sent, errors.New("the file changed while being sent")
	}
	return sent, f.send(screensession.EncodeFile(screensession.FileGetEnd, nil))
}

// close drops a transfer under way when the session ends.
func (f *screenFiles) close() {
	f.abortPut()
	f.mu.Lock()
	if f.getCancel != nil {
		f.getCancel()
	}
	f.mu.Unlock()
}

// listing is the FileListing payload: a folder's content, or with no
// path the places to start from.
type listing struct {
	Path      string              `json:"path"`
	Parent    string              `json:"parent"` // "" back to the places
	Places    []usersession.Place `json:"places,omitempty"`
	Entries   []listEntry         `json:"entries"`
	Truncated bool                `json:"truncated,omitempty"`
}

type listEntry struct {
	Name     string    `json:"name"`
	Dir      bool      `json:"dir,omitempty"`
	Size     int64     `json:"size,omitempty"`
	Modified time.Time `json:"modified,omitzero"`
}

// maxListing bounds the entries listed: the reply must fit one frame.
const maxListing = 1000

// list returns the JSON listing of path, or of the places when empty.
func (f *screenFiles) list(path string) ([]byte, error) {
	path = strings.Trim(strings.TrimSpace(path), `"`)
	l := listing{Path: path, Entries: []listEntry{}}
	if path == "" {
		if f.places != nil {
			l.Places = f.places()
		}
		for _, d := range drives() {
			l.Places = append(l.Places, usersession.Place{Name: strings.TrimRight(d, `\/`), Path: d})
		}
		return json.Marshal(l)
	}
	if !filepath.IsAbs(path) {
		return nil, &fileError{"bad_path", "give the full path of the folder"}
	}
	path = filepath.Clean(path)
	l.Path = path
	if parent := filepath.Dir(path); parent != path {
		l.Parent = parent
	}
	entries, err := os.ReadDir(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, &fileError{"not_found", "folder not found"}
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		le := listEntry{Name: e.Name(), Dir: e.IsDir()}
		info, err := e.Info()
		if err == nil {
			// Junctions and links to folders open like folders.
			if info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
				if st, err := os.Stat(filepath.Join(path, e.Name())); err == nil {
					info, le.Dir = st, st.IsDir()
				}
			}
			le.Modified = info.ModTime().UTC().Truncate(time.Second)
			if !le.Dir {
				le.Size = info.Size()
			}
		}
		l.Entries = append(l.Entries, le)
	}
	sort.Slice(l.Entries, func(i, j int) bool {
		a, b := l.Entries[i], l.Entries[j]
		if a.Dir != b.Dir {
			return a.Dir
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	if len(l.Entries) > maxListing {
		l.Entries, l.Truncated = l.Entries[:maxListing], true
	}
	for {
		b, err := json.Marshal(l)
		if err != nil || len(b) <= screensession.FileChunk {
			return b, err
		}
		l.Entries, l.Truncated = l.Entries[:len(l.Entries)*9/10], true
	}
}

// drives returns the roots to browse from: the drive letters present on
// Windows, / elsewhere.
func drives() []string {
	if runtime.GOOS != "windows" {
		return []string{"/"}
	}
	var out []string
	for c := 'A'; c <= 'Z'; c++ {
		d := string(c) + `:\`
		if _, err := os.Stat(d); err == nil {
			out = append(out, d)
		}
	}
	return out
}
