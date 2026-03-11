package enclave

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/syndtr/goleveldb/leveldb/storage"
)

// noFlockStorage implements storage.Storage for environments where flock(2) is
// not supported (e.g., Gramine SGX passthrough files returning ENOSYS).
//
// It is functionally identical to goleveldb's fileStorage but replaces the
// flock-based file lock with a sync.Mutex. This is safe because story-kernel
// runs as a single process inside the SGX enclave.
type noFlockStorage struct {
	path string

	mu      sync.Mutex
	slock   *noFlockLock
	logw    *os.File
	logSize int64
	buf     []byte
	open    int // negative means closed
	day     int
}

type noFlockLock struct {
	fs *noFlockStorage
}

func (l *noFlockLock) Unlock() {
	if l.fs != nil {
		l.fs.mu.Lock()
		defer l.fs.mu.Unlock()
		if l.fs.slock == l {
			l.fs.slock = nil
		}
	}
}

const logSizeThreshold = 1024 * 1024 // 1 MiB

// openNoFlockStorage creates a file-based storage without flock.
// It provides the same persistence guarantees as goleveldb's fileStorage.
func openNoFlockStorage(path string) (storage.Storage, error) {
	if fi, err := os.Stat(path); err == nil {
		if !fi.IsDir() {
			return nil, fmt.Errorf("leveldb/storage: open %s: not a directory", path)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	logw, err := os.OpenFile(filepath.Join(path, "LOG"), os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	logSize, err := logw.Seek(0, io.SeekEnd)
	if err != nil {
		logw.Close()
		return nil, err
	}

	fs := &noFlockStorage{
		path:    path,
		logw:    logw,
		logSize: logSize,
	}
	runtime.SetFinalizer(fs, (*noFlockStorage).Close)

	return fs, nil
}

func (fs *noFlockStorage) Lock() (storage.Locker, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.open < 0 {
		return nil, storage.ErrClosed
	}
	if fs.slock != nil {
		return nil, storage.ErrLocked
	}
	fs.slock = &noFlockLock{fs: fs}
	return fs.slock, nil
}

func (fs *noFlockStorage) printDay(t time.Time) {
	if fs.day == t.Day() {
		return
	}
	fs.day = t.Day()
	_, _ = fs.logw.Write([]byte("=============== " + t.Format("Jan 2, 2006 (MST)") + " ===============\n"))
}

func (fs *noFlockStorage) doLog(t time.Time, str string) {
	if fs.logSize > logSizeThreshold {
		fs.logw.Close()
		fs.logw = nil
		fs.logSize = 0
		_ = os.Rename(filepath.Join(fs.path, "LOG"), filepath.Join(fs.path, "LOG.old"))
	}
	if fs.logw == nil {
		var err error
		fs.logw, err = os.OpenFile(filepath.Join(fs.path, "LOG"), os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return
		}
		fs.day = 0
	}
	fs.printDay(t)
	hour, min, sec := t.Clock()
	msec := t.Nanosecond() / 1e3
	fs.buf = itoa(fs.buf[:0], hour, 2)
	fs.buf = append(fs.buf, ':')
	fs.buf = itoa(fs.buf, min, 2)
	fs.buf = append(fs.buf, ':')
	fs.buf = itoa(fs.buf, sec, 2)
	fs.buf = append(fs.buf, '.')
	fs.buf = itoa(fs.buf, msec, 6)
	fs.buf = append(fs.buf, ' ')
	fs.buf = append(fs.buf, []byte(str)...)
	fs.buf = append(fs.buf, '\n')
	n, _ := fs.logw.Write(fs.buf)
	fs.logSize += int64(n)
}

func (fs *noFlockStorage) Log(str string) {
	t := time.Now()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.open < 0 {
		return
	}
	fs.doLog(t, str)
}

func (fs *noFlockStorage) log(str string) {
	fs.doLog(time.Now(), str)
}

func (fs *noFlockStorage) SetMeta(fd storage.FileDesc) error {
	if !storage.FileDescOk(fd) {
		return storage.ErrInvalidFile
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.open < 0 {
		return storage.ErrClosed
	}
	return fs.setMeta(fd)
}

func (fs *noFlockStorage) setMeta(fd storage.FileDesc) error {
	content := genName(fd) + "\n"
	currentPath := filepath.Join(fs.path, "CURRENT")
	if _, err := os.Stat(currentPath); err == nil {
		b, err := os.ReadFile(currentPath)
		if err != nil {
			fs.log(fmt.Sprintf("backup CURRENT: %v", err))
			return err
		}
		if string(b) == content {
			return nil
		}
		if err := writeFileSynced(filepath.Join(fs.path, "CURRENT.bak"), b, 0644); err != nil {
			fs.log(fmt.Sprintf("backup CURRENT: %v", err))
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmpPath := fmt.Sprintf("%s.%d", currentPath, fd.Num)
	if err := writeFileSynced(tmpPath, []byte(content), 0644); err != nil {
		fs.log(fmt.Sprintf("create CURRENT.%d: %v", fd.Num, err))
		return err
	}
	if err := os.Rename(tmpPath, currentPath); err != nil {
		fs.log(fmt.Sprintf("rename CURRENT.%d: %v", fd.Num, err))
		return err
	}
	if err := syncDir(fs.path); err != nil {
		fs.log(fmt.Sprintf("syncDir: %v", err))
		return err
	}
	return nil
}

func (fs *noFlockStorage) GetMeta() (storage.FileDesc, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.open < 0 {
		return storage.FileDesc{}, storage.ErrClosed
	}

	dir, err := os.Open(fs.path)
	if err != nil {
		return storage.FileDesc{}, err
	}
	names, err := dir.Readdirnames(0)
	if ce := dir.Close(); ce != nil {
		fs.log(fmt.Sprintf("close dir: %v", ce))
	}
	if err != nil {
		return storage.FileDesc{}, err
	}

	type currentFile struct {
		name string
		fd   storage.FileDesc
	}
	tryCurrent := func(name string) (*currentFile, error) {
		b, err := os.ReadFile(filepath.Join(fs.path, name))
		if err != nil {
			if os.IsNotExist(err) {
				err = os.ErrNotExist
			}
			return nil, err
		}
		var fd storage.FileDesc
		if len(b) < 1 || b[len(b)-1] != '\n' || !parseNamePtr(string(b[:len(b)-1]), &fd) {
			err := &storage.ErrCorrupted{
				Err: errors.New("leveldb/storage: corrupted or incomplete CURRENT file"),
			}
			return nil, err
		}
		if _, err := os.Stat(filepath.Join(fs.path, genName(fd))); err != nil {
			if os.IsNotExist(err) {
				fs.log(fmt.Sprintf("%s: missing target file: %s", name, fd))
				err = os.ErrNotExist
			}
			return nil, err
		}
		return &currentFile{name: name, fd: fd}, nil
	}
	tryCurrents := func(names []string) (*currentFile, error) {
		var (
			cur      *currentFile
			lastCerr error
		)
		for _, name := range names {
			var err error
			cur, err = tryCurrent(name)
			if err == nil {
				break
			} else if errors.Is(err, os.ErrNotExist) {
				continue
			} else if isCorrupted(err) {
				lastCerr = err
				continue
			} else {
				return nil, err
			}
		}
		if cur == nil {
			err := os.ErrNotExist
			if lastCerr != nil {
				err = lastCerr
			}
			return nil, err
		}
		return cur, nil
	}

	var nums []int64
	for _, name := range names {
		if strings.HasPrefix(name, "CURRENT.") && name != "CURRENT.bak" {
			i, err := strconv.ParseInt(name[8:], 10, 64)
			if err == nil {
				nums = append(nums, i)
			}
		}
	}
	var (
		pendCur   *currentFile
		pendErr   = os.ErrNotExist
		pendNames []string
	)
	if len(nums) > 0 {
		sort.Sort(sort.Reverse(int64Slice(nums)))
		pendNames = make([]string, len(nums))
		for i, num := range nums {
			pendNames[i] = fmt.Sprintf("CURRENT.%d", num)
		}
		pendCur, pendErr = tryCurrents(pendNames)
		if pendErr != nil && !errors.Is(pendErr, os.ErrNotExist) && !isCorrupted(pendErr) {
			return storage.FileDesc{}, pendErr
		}
	}

	curCur, curErr := tryCurrents([]string{"CURRENT", "CURRENT.bak"})
	if curErr != nil && !errors.Is(curErr, os.ErrNotExist) && !isCorrupted(curErr) {
		return storage.FileDesc{}, curErr
	}

	if pendCur != nil && (curCur == nil || pendCur.fd.Num > curCur.fd.Num) {
		curCur = pendCur
	}

	if curCur != nil {
		if curCur.name != "CURRENT" || len(pendNames) != 0 {
			if err := fs.setMeta(curCur.fd); err == nil {
				for _, name := range pendNames {
					if err := os.Remove(filepath.Join(fs.path, name)); err != nil {
						fs.log(fmt.Sprintf("remove %s: %v", name, err))
					}
				}
			}
		}
		return curCur.fd, nil
	}

	if isCorrupted(pendErr) {
		return storage.FileDesc{}, pendErr
	}
	return storage.FileDesc{}, curErr
}

func (fs *noFlockStorage) List(ft storage.FileType) (fds []storage.FileDesc, err error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.open < 0 {
		return nil, storage.ErrClosed
	}
	dir, err := os.Open(fs.path)
	if err != nil {
		return
	}
	names, err := dir.Readdirnames(0)
	if cerr := dir.Close(); cerr != nil {
		fs.log(fmt.Sprintf("close dir: %v", cerr))
	}
	if err == nil {
		for _, name := range names {
			if fd, ok := parseName(name); ok && fd.Type&ft != 0 {
				fds = append(fds, fd)
			}
		}
	}
	return
}

func (fs *noFlockStorage) Open(fd storage.FileDesc) (storage.Reader, error) {
	if !storage.FileDescOk(fd) {
		return nil, storage.ErrInvalidFile
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.open < 0 {
		return nil, storage.ErrClosed
	}
	of, err := os.OpenFile(filepath.Join(fs.path, genName(fd)), os.O_RDONLY, 0)
	if err != nil {
		if hasOldName(fd) && os.IsNotExist(err) {
			of, err = os.OpenFile(filepath.Join(fs.path, genOldName(fd)), os.O_RDONLY, 0)
			if err == nil {
				goto ok
			}
		}
		return nil, err
	}
ok:
	fs.open++
	return &noFlockFileWrap{File: of, fs: fs, fd: fd}, nil
}

func (fs *noFlockStorage) Create(fd storage.FileDesc) (storage.Writer, error) {
	if !storage.FileDescOk(fd) {
		return nil, storage.ErrInvalidFile
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.open < 0 {
		return nil, storage.ErrClosed
	}
	of, err := os.OpenFile(filepath.Join(fs.path, genName(fd)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	fs.open++
	return &noFlockFileWrap{File: of, fs: fs, fd: fd}, nil
}

func (fs *noFlockStorage) Remove(fd storage.FileDesc) error {
	if !storage.FileDescOk(fd) {
		return storage.ErrInvalidFile
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.open < 0 {
		return storage.ErrClosed
	}
	err := os.Remove(filepath.Join(fs.path, genName(fd)))
	if err != nil {
		if hasOldName(fd) && os.IsNotExist(err) {
			if e1 := os.Remove(filepath.Join(fs.path, genOldName(fd))); !os.IsNotExist(e1) {
				fs.log(fmt.Sprintf("remove %s: %v (old name)", fd, err))
				err = e1
			}
		} else {
			fs.log(fmt.Sprintf("remove %s: %v", fd, err))
		}
	}
	return err
}

func (fs *noFlockStorage) Rename(oldfd, newfd storage.FileDesc) error {
	if !storage.FileDescOk(oldfd) || !storage.FileDescOk(newfd) {
		return storage.ErrInvalidFile
	}
	if oldfd == newfd {
		return nil
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.open < 0 {
		return storage.ErrClosed
	}
	return os.Rename(filepath.Join(fs.path, genName(oldfd)), filepath.Join(fs.path, genName(newfd)))
}

func (fs *noFlockStorage) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.open < 0 {
		return storage.ErrClosed
	}
	runtime.SetFinalizer(fs, nil)

	if fs.open > 0 {
		fs.log(fmt.Sprintf("close: warning, %d files still open", fs.open))
	}
	fs.open = -1
	if fs.logw != nil {
		fs.logw.Close()
	}
	return nil
}

// noFlockFileWrap wraps os.File with open-count tracking and manifest sync.
type noFlockFileWrap struct {
	*os.File
	fs     *noFlockStorage
	fd     storage.FileDesc
	closed bool
}

func (fw *noFlockFileWrap) Sync() error {
	if err := fw.File.Sync(); err != nil {
		return err
	}
	if fw.fd.Type == storage.TypeManifest {
		if err := syncDir(fw.fs.path); err != nil {
			fw.fs.log(fmt.Sprintf("syncDir: %v", err))
			return err
		}
	}
	return nil
}

func (fw *noFlockFileWrap) Close() error {
	fw.fs.mu.Lock()
	defer fw.fs.mu.Unlock()
	if fw.closed {
		return storage.ErrClosed
	}
	fw.closed = true
	fw.fs.open--
	err := fw.File.Close()
	if err != nil {
		fw.fs.log(fmt.Sprintf("close %s: %v", fw.fd, err))
	}
	return err
}

////////////////////////////////////////////////////////////////////////////////
// Helpers (mirrored from goleveldb's unexported functions)
////////////////////////////////////////////////////////////////////////////////

type int64Slice []int64

func (p int64Slice) Len() int           { return len(p) }
func (p int64Slice) Less(i, j int) bool { return p[i] < p[j] }
func (p int64Slice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func itoa(buf []byte, i int, wid int) []byte {
	u := uint(i)
	if u == 0 && wid <= 1 {
		return append(buf, '0')
	}
	var b [32]byte
	bp := len(b)
	for ; u > 0 || wid > 0; u /= 10 {
		bp--
		wid--
		b[bp] = byte(u%10) + '0'
	}
	return append(buf, b[bp:]...)
}

func writeFileSynced(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Sync(); err == nil {
		err = err1
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

func syncDir(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !isErrInvalid(err) {
		return err
	}
	return nil
}

func isErrInvalid(err error) bool {
	if errors.Is(err, os.ErrInvalid) {
		return true
	}
	if errors.Is(err, syscall.EINVAL) {
		return true
	}
	return false
}

func genName(fd storage.FileDesc) string {
	switch fd.Type {
	case storage.TypeManifest:
		return fmt.Sprintf("MANIFEST-%06d", fd.Num)
	case storage.TypeJournal:
		return fmt.Sprintf("%06d.log", fd.Num)
	case storage.TypeTable:
		return fmt.Sprintf("%06d.ldb", fd.Num)
	case storage.TypeTemp:
		return fmt.Sprintf("%06d.tmp", fd.Num)
	default:
		panic("invalid file type")
	}
}

func hasOldName(fd storage.FileDesc) bool {
	return fd.Type == storage.TypeTable
}

func genOldName(fd storage.FileDesc) string {
	if fd.Type == storage.TypeTable {
		return fmt.Sprintf("%06d.sst", fd.Num)
	}
	return genName(fd)
}

func parseName(name string) (fd storage.FileDesc, ok bool) {
	var tail string
	_, err := fmt.Sscanf(name, "%d.%s", &fd.Num, &tail)
	if err == nil {
		switch tail {
		case "log":
			fd.Type = storage.TypeJournal
		case "ldb", "sst":
			fd.Type = storage.TypeTable
		case "tmp":
			fd.Type = storage.TypeTemp
		default:
			return
		}
		return fd, true
	}
	n, _ := fmt.Sscanf(name, "MANIFEST-%d%s", &fd.Num, &tail)
	if n == 1 {
		fd.Type = storage.TypeManifest
		return fd, true
	}
	return
}

func parseNamePtr(name string, fd *storage.FileDesc) bool {
	_fd, ok := parseName(name)
	if fd != nil {
		*fd = _fd
	}
	return ok
}

func isCorrupted(err error) bool {
	var cerr *storage.ErrCorrupted
	return errors.As(err, &cerr)
}

// isFlockUnsupported returns true if the error indicates that flock(2)
// is not supported (ENOSYS / ENOTSUP), as occurs in Gramine SGX.
func isFlockUnsupported(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ENOSYS || errno == syscall.ENOTSUP
	}
	errStr := err.Error()
	return strings.Contains(errStr, "function not implemented") ||
		strings.Contains(errStr, "not supported")
}

// OpenFileNoFlock opens a goleveldb storage. It first tries the standard
// storage.OpenFile (which uses flock). If flock is unsupported (SGX/Gramine),
// it falls back to a file-based storage with sync.Mutex instead of flock.
func OpenFileNoFlock(path string) (storage.Storage, error) {
	stor, err := storage.OpenFile(path, false)
	if err == nil {
		return stor, nil
	}
	if !isFlockUnsupported(err) {
		return nil, err
	}
	return openNoFlockStorage(path)
}
