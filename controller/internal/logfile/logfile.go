// Package logfile is a log file that keeps itself within an age limit and a disk limit (SDN-54,
// #247, user story 57 of #224: logs never fill a disk). A Writer appends to one active file. It
// starts a new file when the active one is full and when a new day (UTC) begins, and it deletes
// the files it moved aside, the oldest first, when they are past the age limit or when they would
// take the room of the active file away. It writes the log of the Controller service; the log of
// the Node itself is written by LogWriter.c, which follows the same rules.
//
// The age limit: a file whose last write is older than the limit is deleted. A file holds the
// records of one day at most, so a record stays for the limit and for a day more at the most.
//
// The disk limit: the files of the log never take more than the limit together. The active file
// may grow to its full size, so the files that were moved aside leave room for that much: a log
// that has reached its limit never passes it, not even between a rotation and the deletion that
// follows it.
//
// A limit that the system keeps a Writer from meeting, a file that another program holds open and
// so cannot be deleted, is tried again at the next rotation and at the hourly sweep, and Inspect
// tells whether the files are within the limits now.
package logfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultMaxAgeDays is the age limit of a log that none was set for, in days.
	DefaultMaxAgeDays = 30
	// DefaultMaxMB is the disk limit of a log that none was set for, in megabytes.
	DefaultMaxMB = 256
	// DefaultFileBytes is the size at which the active file of a log without a disk limit is
	// rotated.
	DefaultFileBytes = 64 << 20
)

const (
	// sweepEvery is how often a Writer applies its limits while nothing is written.
	sweepEvery = time.Hour
	// rotateRetry is how long a Writer waits before it rotates again after a rotation failed.
	rotateRetry = time.Minute
	// stampLayout is the time in the name of a file that was moved aside: the UTC time of the
	// rotation, to the millisecond.
	stampLayout = "20060102T150405.000Z"
)

// Limits are what the files of a log stay within. A limit of 0 is no limit.
type Limits struct {
	// MaxAge is the age at which a file that was moved aside is deleted, by its last write.
	MaxAge time.Duration
	// MaxBytes is what all the files of the log may take together, the active file at its largest
	// included.
	MaxBytes int64
	// MaxFileBytes is the size at which the active file is rotated. Zero makes it a quarter of
	// MaxBytes, or DefaultFileBytes without a disk limit. It is never more than MaxBytes.
	MaxFileBytes int64
}

// DefaultLimits returns the limits of a log that none were set for: DefaultMaxAgeDays days and
// DefaultMaxMB megabytes.
func DefaultLimits() Limits {
	return LimitsOf(DefaultMaxAgeDays, DefaultMaxMB)
}

// LimitsOf returns the limits of days days and megabytes megabytes, 0 for none: the form in which
// the flags of the controller give them.
func LimitsOf(days, megabytes int) Limits {
	return Limits{MaxAge: time.Duration(days) * 24 * time.Hour, MaxBytes: int64(megabytes) << 20}
}

// fileLimit returns the size at which the active file is rotated.
func (l Limits) fileLimit() int64 {
	size := l.MaxFileBytes
	if size == 0 {
		size = DefaultFileBytes
		if l.MaxBytes > 0 {
			size = max(l.MaxBytes/4, 1)
		}
	}
	if l.MaxBytes > 0 {
		size = min(size, l.MaxBytes)
	}
	return size
}

// File is one file of a log.
type File struct {
	// Name is the name of the file in the directory of the log.
	Name string `json:"name"`
	// Size is its size in bytes.
	Size int64 `json:"size"`
	// ModTime is the time of its last write.
	ModTime time.Time `json:"modified"`
	// Active is true for the file that is written to now.
	Active bool `json:"active,omitempty"`
}

// Files returns the files of the log whose active file is path: the ones that were moved aside
// from it, the oldest first, and then that file. The name of a file moved aside holds the time of
// its rotation, so the names put the files in the order of their records, whatever the resolution
// of the clock of the file system. A directory that does not exist holds none.
func Files(path string) ([]File, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []File
	for _, e := range entries {
		name := e.Name()
		if name != base && !movedAside(name, stem, ext) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			// A file that is gone again, or a directory of that name, is no file of the log.
			continue
		}
		if name == base {
			if fresh, err := statOpen(filepath.Join(dir, name)); err == nil {
				info = fresh
			}
		}
		out = append(out, File{Name: name, Size: info.Size(), ModTime: info.ModTime(), Active: name == base})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[j].Active
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// statOpen returns what a handle to the file at path says of it. The active file of a log is open
// for writing, and on Windows a directory listing, and so os.Stat too, gives the size and the time
// that the file had when its last writer closed it: too small a size for a log that is being
// written, which only the handle of an open file knows.
func statOpen(path string) (fs.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

// movedAside reports whether name is the name of a file that was moved aside from the active file
// stem+ext: the stem, a dot, a stamp, and the extension.
func movedAside(name, stem, ext string) bool {
	return len(name) > len(stem)+len(ext)+1 && strings.HasPrefix(name, stem+".") && strings.HasSuffix(name, ext)
}

// Usage is what the files of a log take, as Inspect finds it.
type Usage struct {
	// Files are the files of the log in the order of Files.
	Files []File `json:"files"`
	// Bytes is what they take together.
	Bytes int64 `json:"bytes"`
	// Within is true when no file that was moved aside is past the age limit and they take no
	// more than the disk limit.
	Within bool `json:"withinLimits"`
}

// Inspect returns the files of the log whose active file is path, what they take and whether that
// is within limits at now.
func Inspect(path string, limits Limits, now time.Time) (Usage, error) {
	files, err := Files(path)
	if err != nil {
		return Usage{}, err
	}
	u := Usage{Files: files, Within: true}
	for _, f := range files {
		u.Bytes += f.Size
		if !f.Active && limits.MaxAge > 0 && now.Sub(f.ModTime) > limits.MaxAge {
			u.Within = false
		}
	}
	if limits.MaxBytes > 0 && u.Bytes > limits.MaxBytes {
		u.Within = false
	}
	return u, nil
}

// Writer is a log file within its limits. It is safe for concurrent use.
type Writer struct {
	path    string
	dir     string
	stem    string
	ext     string
	limits  Limits
	maxFile int64
	now     func() time.Time

	// mu guards what follows.
	mu sync.Mutex
	// f is the active file, nil while it could not be opened or once the writer is closed.
	f *os.File
	// closed is true once Close was called.
	closed bool
	// size is the size of the active file.
	size int64
	// started is the time of the first record of the active file, or its last write when it
	// existed before this writer.
	started time.Time
	// retry is the time before which no rotation is tried, after one failed.
	retry time.Time

	stop chan struct{}
	done chan struct{}
}

// New opens the log file path, which it creates with its directory when they are not there, and
// keeps its files within limits. It applies the limits at once, so limits that are lower than the
// ones of the last run take effect at the start, and again every hour while the program runs.
func New(path string, limits Limits) (*Writer, error) {
	return newWriter(path, limits, time.Now, sweepEvery)
}

func newWriter(path string, limits Limits, now func() time.Time, every time.Duration) (*Writer, error) {
	if limits.MaxAge < 0 || limits.MaxBytes < 0 || limits.MaxFileBytes < 0 {
		return nil, errors.New("a limit of the log is negative")
	}
	dir, base := filepath.Dir(path), filepath.Base(path)
	ext := filepath.Ext(base)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("the log directory: %w", err)
	}
	w := &Writer{path: path, dir: dir, stem: strings.TrimSuffix(base, ext), ext: ext, limits: limits, maxFile: limits.fileLimit(),
		now: now, stop: make(chan struct{}), done: make(chan struct{})}
	t := now()
	w.mu.Lock()
	err := w.open(t)
	if err == nil {
		w.tick(t)
	}
	w.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("the log file: %w", err)
	}
	go w.sweeper(every)
	return w, nil
}

// Path returns the path of the active file.
func (w *Writer) Path() string {
	return w.path
}

// Write appends p to the active file. It first rotates the file when p does not fit in it or a new
// day began. A p longer than a file may be is cut to the size of a file: the limit holds before
// the record does.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	all := len(p)
	if int64(len(p)) > w.maxFile {
		p = p[:w.maxFile]
	}
	now := w.now()
	if w.f != nil {
		if w.size == 0 {
			w.started = now
		}
		if w.full(now, int64(len(p))) {
			w.rotate(now)
		}
	}
	if w.f == nil {
		if err := w.open(now); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	if err != nil {
		return n, err
	}
	return all, nil
}

// full reports whether the active file must be rotated before add bytes are written to it.
func (w *Writer) full(now time.Time, add int64) bool {
	if w.size == 0 || now.Before(w.retry) {
		return false
	}
	return w.size+add > w.maxFile || !sameDay(w.started, now)
}

// sameDay reports whether a and b are on the same UTC day.
func sameDay(a, b time.Time) bool {
	ay, am, ad := a.UTC().Date()
	by, bm, bd := b.UTC().Date()
	return ay == by && am == bm && ad == bd
}

// open opens the active file, which may exist, to append to it. The caller holds mu.
func (w *Writer) open(now time.Time) error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size, w.started = f, info.Size(), now
	if w.size > 0 {
		w.started = info.ModTime()
	}
	return nil
}

// tick applies the limits at now, with the active file rotated first when it holds the records of
// an earlier day or has no room left, which a start and the sweep of an idle log do. The caller
// holds mu.
func (w *Writer) tick(now time.Time) {
	if w.f != nil && w.size > 0 && (w.size >= w.maxFile || !sameDay(w.started, now)) {
		w.rotate(now)
		return
	}
	w.sweep(now)
}

// rotate moves the active file aside under a name with the time of now, applies the limits and
// opens a new active file. A file that cannot be moved aside stays the active one, and the
// rotation is tried again after rotateRetry. A new file that cannot be opened is tried again at
// the next write. The caller holds mu.
func (w *Writer) rotate(now time.Time) {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	err := os.Rename(w.path, w.movedPath(now))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		w.retry = now.Add(rotateRetry)
	} else {
		w.sweep(now)
	}
	_ = w.open(now)
}

// movedPath returns the path that the active file gets when it is moved aside at now: the stem,
// the time and the extension, and a number after the time when a file of that name exists, which
// sorts after the name without one.
func (w *Writer) movedPath(now time.Time) string {
	stamp := now.UTC().Format(stampLayout)
	p := filepath.Join(w.dir, w.stem+"."+stamp+w.ext)
	for i := 1; i < 1000; i++ {
		if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
			break
		}
		p = filepath.Join(w.dir, fmt.Sprintf("%s.%s~%03d%s", w.stem, stamp, i, w.ext))
	}
	return p
}

// sweep deletes the files moved aside that are past the age limit at now, and then the oldest
// ones until the rest leave the active file the room to grow to its full size. A file that cannot
// be deleted stays. The caller holds mu.
func (w *Writer) sweep(now time.Time) {
	files, err := Files(w.path)
	if err != nil {
		return
	}
	var kept []File
	var total int64
	for _, f := range files {
		if f.Active {
			continue
		}
		if w.limits.MaxAge > 0 && now.Sub(f.ModTime) > w.limits.MaxAge && w.remove(f) {
			continue
		}
		kept = append(kept, f)
		total += f.Size
	}
	if w.limits.MaxBytes == 0 {
		return
	}
	for _, f := range kept {
		if total+w.maxFile <= w.limits.MaxBytes {
			break
		}
		if w.remove(f) {
			total -= f.Size
		}
	}
}

// remove deletes the file f of the log and reports whether it is gone.
func (w *Writer) remove(f File) bool {
	err := os.Remove(filepath.Join(w.dir, f.Name))
	return err == nil || errors.Is(err, fs.ErrNotExist)
}

// sweeper applies the limits every `every` until the writer is closed, so that the files of a log
// that nothing is written to still age out.
func (w *Writer) sweeper(every time.Duration) {
	defer close(w.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.mu.Lock()
			if !w.closed {
				w.tick(w.now())
			}
			w.mu.Unlock()
		}
	}
}

// Close closes the active file and stops the sweep. It is safe to call it more than once.
func (w *Writer) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	close(w.stop)
	var err error
	if w.f != nil {
		err = w.f.Close()
		w.f = nil
	}
	w.mu.Unlock()
	<-w.done
	return err
}
