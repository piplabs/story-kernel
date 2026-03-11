package enclave

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

func TestOpenNoFlockStorage_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testdb")

	stor, err := openNoFlockStorage(path)
	require.NoError(t, err)
	defer stor.Close()

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, fi.IsDir())

	// LOG file should be created
	_, err = os.Stat(filepath.Join(path, "LOG"))
	require.NoError(t, err)
}

func TestOpenNoFlockStorage_ExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testdb")
	require.NoError(t, os.MkdirAll(path, 0755))

	stor, err := openNoFlockStorage(path)
	require.NoError(t, err)
	defer stor.Close()
}

func TestOpenNoFlockStorage_NotADirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")

	// Create a file (not a directory) at the path
	require.NoError(t, os.WriteFile(path, []byte("data"), 0644))

	_, err := openNoFlockStorage(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

func TestNoFlockStorage_Lock(t *testing.T) {
	stor := newTestStorage(t)

	// First lock should succeed
	lock, err := stor.Lock()
	require.NoError(t, err)
	require.NotNil(t, lock)

	// Second lock should fail (already locked)
	_, err = stor.Lock()
	assert.ErrorIs(t, err, storage.ErrLocked)

	// Unlock and re-lock should succeed
	lock.Unlock()
	lock2, err := stor.Lock()
	require.NoError(t, err)
	require.NotNil(t, lock2)
	lock2.Unlock()
}

func TestNoFlockStorage_LockAfterClose(t *testing.T) {
	stor := newTestStorage(t)
	require.NoError(t, stor.Close())

	_, err := stor.Lock()
	assert.ErrorIs(t, err, storage.ErrClosed)
}

func TestNoFlockStorage_CreateAndOpen(t *testing.T) {
	stor := newTestStorage(t)

	fd := storage.FileDesc{Type: storage.TypeTable, Num: 1}
	data := []byte("hello world")

	// Create file
	w, err := stor.Create(fd)
	require.NoError(t, err)
	_, err = w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Open and read file
	r, err := stor.Open(fd)
	require.NoError(t, err)
	buf := make([]byte, len(data))
	_, err = r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, data, buf)
	require.NoError(t, r.Close())
}

func TestNoFlockStorage_CreateOverwrites(t *testing.T) {
	stor := newTestStorage(t)

	fd := storage.FileDesc{Type: storage.TypeTable, Num: 1}

	// Write initial data
	w, err := stor.Create(fd)
	require.NoError(t, err)
	_, _ = w.Write([]byte("old data"))
	require.NoError(t, w.Close())

	// Overwrite with new data
	w, err = stor.Create(fd)
	require.NoError(t, err)
	_, _ = w.Write([]byte("new"))
	require.NoError(t, w.Close())

	// Read back
	r, err := stor.Open(fd)
	require.NoError(t, err)
	buf := make([]byte, 3)
	_, err = r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), buf)
	require.NoError(t, r.Close())
}

func TestNoFlockStorage_Remove(t *testing.T) {
	stor := newTestStorage(t)

	fd := storage.FileDesc{Type: storage.TypeTable, Num: 1}

	// Create then remove
	w, err := stor.Create(fd)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	require.NoError(t, stor.Remove(fd))

	// Open should fail after removal
	_, err = stor.Open(fd)
	assert.Error(t, err)
}

func TestNoFlockStorage_Rename(t *testing.T) {
	stor := newTestStorage(t)

	oldFd := storage.FileDesc{Type: storage.TypeTable, Num: 1}
	newFd := storage.FileDesc{Type: storage.TypeTable, Num: 2}

	// Create file
	w, err := stor.Create(oldFd)
	require.NoError(t, err)
	_, _ = w.Write([]byte("data"))
	require.NoError(t, w.Close())

	// Rename
	require.NoError(t, stor.Rename(oldFd, newFd))

	// Old name should not exist
	_, err = stor.Open(oldFd)
	assert.Error(t, err)

	// New name should exist
	r, err := stor.Open(newFd)
	require.NoError(t, err)
	require.NoError(t, r.Close())
}

func TestNoFlockStorage_RenameSameFile(t *testing.T) {
	stor := newTestStorage(t)

	fd := storage.FileDesc{Type: storage.TypeTable, Num: 1}

	// Create file
	w, err := stor.Create(fd)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Rename to self should be a no-op
	require.NoError(t, stor.Rename(fd, fd))

	// File should still exist
	r, err := stor.Open(fd)
	require.NoError(t, err)
	require.NoError(t, r.Close())
}

func TestNoFlockStorage_List(t *testing.T) {
	stor := newTestStorage(t)

	// Create multiple files
	for _, fd := range []storage.FileDesc{
		{Type: storage.TypeTable, Num: 1},
		{Type: storage.TypeTable, Num: 2},
		{Type: storage.TypeJournal, Num: 3},
	} {
		w, err := stor.Create(fd)
		require.NoError(t, err)
		require.NoError(t, w.Close())
	}

	// List tables only
	fds, err := stor.List(storage.TypeTable)
	require.NoError(t, err)
	assert.Len(t, fds, 2)

	// List journals only
	fds, err = stor.List(storage.TypeJournal)
	require.NoError(t, err)
	assert.Len(t, fds, 1)

	// List all
	fds, err = stor.List(storage.TypeAll)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(fds), 3)
}

func TestNoFlockStorage_SetGetMeta(t *testing.T) {
	stor := newTestStorage(t)

	fd := storage.FileDesc{Type: storage.TypeManifest, Num: 1}

	// Create the manifest file so GetMeta can find it
	w, err := stor.Create(fd)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// SetMeta
	require.NoError(t, stor.SetMeta(fd))

	// GetMeta should return the same descriptor
	got, err := stor.GetMeta()
	require.NoError(t, err)
	assert.Equal(t, fd, got)
}

func TestNoFlockStorage_SetMetaIdempotent(t *testing.T) {
	stor := newTestStorage(t)

	fd := storage.FileDesc{Type: storage.TypeManifest, Num: 1}
	w, err := stor.Create(fd)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Set same meta twice (second call should be a no-op)
	require.NoError(t, stor.SetMeta(fd))
	require.NoError(t, stor.SetMeta(fd))

	got, err := stor.GetMeta()
	require.NoError(t, err)
	assert.Equal(t, fd, got)
}

func TestNoFlockStorage_InvalidFileDesc(t *testing.T) {
	stor := newTestStorage(t)

	invalid := storage.FileDesc{} // zero value is invalid

	_, err := stor.Open(invalid)
	assert.ErrorIs(t, err, storage.ErrInvalidFile)

	_, err = stor.Create(invalid)
	assert.ErrorIs(t, err, storage.ErrInvalidFile)

	err = stor.Remove(invalid)
	assert.ErrorIs(t, err, storage.ErrInvalidFile)

	err = stor.SetMeta(invalid)
	assert.ErrorIs(t, err, storage.ErrInvalidFile)
}

func TestNoFlockStorage_OperationsAfterClose(t *testing.T) {
	stor := newTestStorage(t)
	require.NoError(t, stor.Close())

	fd := storage.FileDesc{Type: storage.TypeTable, Num: 1}

	_, err := stor.Open(fd)
	assert.ErrorIs(t, err, storage.ErrClosed)

	_, err = stor.Create(fd)
	assert.ErrorIs(t, err, storage.ErrClosed)

	err = stor.Remove(fd)
	assert.ErrorIs(t, err, storage.ErrClosed)

	err = stor.SetMeta(storage.FileDesc{Type: storage.TypeManifest, Num: 1})
	assert.ErrorIs(t, err, storage.ErrClosed)

	_, err = stor.List(storage.TypeAll)
	assert.ErrorIs(t, err, storage.ErrClosed)

	_, err = stor.GetMeta()
	assert.ErrorIs(t, err, storage.ErrClosed)

	// Double close
	assert.ErrorIs(t, stor.Close(), storage.ErrClosed)
}

func TestNoFlockStorage_Log(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testdb")

	stor, err := openNoFlockStorage(path)
	require.NoError(t, err)

	stor.Log("test message")
	stor.Log("another message")

	require.NoError(t, stor.Close())

	// LOG file should contain the messages
	logData, err := os.ReadFile(filepath.Join(path, "LOG"))
	require.NoError(t, err)
	assert.Contains(t, string(logData), "test message")
	assert.Contains(t, string(logData), "another message")
}

func TestNoFlockStorage_ConcurrentAccess(t *testing.T) {
	stor := newTestStorage(t)

	var wg sync.WaitGroup
	errs := make(chan error, 100)

	// Concurrent creates and opens
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			fd := storage.FileDesc{Type: storage.TypeTable, Num: int64(n)}

			w, err := stor.Create(fd)
			if err != nil {
				errs <- err
				return
			}
			_, _ = w.Write([]byte("data"))
			if err := w.Close(); err != nil {
				errs <- err
				return
			}

			r, err := stor.Open(fd)
			if err != nil {
				errs <- err
				return
			}
			if err := r.Close(); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent operation failed: %v", err)
	}
}

func TestNoFlockStorage_LevelDBIntegration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testdb")

	stor, err := openNoFlockStorage(path)
	require.NoError(t, err)

	// Open a real LevelDB on top of noFlockStorage
	db, err := leveldb.Open(stor, nil)
	require.NoError(t, err)

	// Write data
	require.NoError(t, db.Put([]byte("key1"), []byte("value1"), nil))
	require.NoError(t, db.Put([]byte("key2"), []byte("value2"), nil))

	// Read data
	val, err := db.Get([]byte("key1"), nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("value1"), val)

	val, err = db.Get([]byte("key2"), nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("value2"), val)

	require.NoError(t, db.Close())

	// Reopen and verify persistence
	stor2, err := openNoFlockStorage(path)
	require.NoError(t, err)

	db2, err := leveldb.Open(stor2, nil)
	require.NoError(t, err)

	val, err = db2.Get([]byte("key1"), nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("value1"), val)

	require.NoError(t, db2.Close())
}

// Helper name generation tests

func TestGenName(t *testing.T) {
	tests := []struct {
		fd   storage.FileDesc
		want string
	}{
		{storage.FileDesc{Type: storage.TypeManifest, Num: 1}, "MANIFEST-000001"},
		{storage.FileDesc{Type: storage.TypeJournal, Num: 5}, "000005.log"},
		{storage.FileDesc{Type: storage.TypeTable, Num: 42}, "000042.ldb"},
		{storage.FileDesc{Type: storage.TypeTemp, Num: 100}, "000100.tmp"},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.want, genName(tc.fd))
	}
}

func TestParseName(t *testing.T) {
	tests := []struct {
		name   string
		wantOk bool
		wantFd storage.FileDesc
	}{
		{"000001.ldb", true, storage.FileDesc{Type: storage.TypeTable, Num: 1}},
		{"000001.sst", true, storage.FileDesc{Type: storage.TypeTable, Num: 1}},
		{"000005.log", true, storage.FileDesc{Type: storage.TypeJournal, Num: 5}},
		{"000100.tmp", true, storage.FileDesc{Type: storage.TypeTemp, Num: 100}},
		{"MANIFEST-000001", true, storage.FileDesc{Type: storage.TypeManifest, Num: 1}},
		{"CURRENT", false, storage.FileDesc{}},
		{"LOG", false, storage.FileDesc{}},
		{"random.txt", false, storage.FileDesc{}},
	}

	for _, tc := range tests {
		fd, ok := parseName(tc.name)
		assert.Equal(t, tc.wantOk, ok, "parseName(%q)", tc.name)
		if ok {
			assert.Equal(t, tc.wantFd, fd, "parseName(%q)", tc.name)
		}
	}
}

func TestIsFlockUnsupported(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"ENOSYS", syscall.ENOSYS, true},
		{"ENOTSUP", syscall.ENOTSUP, true},
		{"ENOENT", syscall.ENOENT, false},
		{"generic error", errors.New("some error"), false},
		{"function not implemented string", errors.New("function not implemented"), true},
		{"not supported string", errors.New("operation not supported"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isFlockUnsupported(tc.err))
		})
	}
}

// newTestStorage creates a noFlockStorage in a temp directory for testing.
func newTestStorage(t *testing.T) storage.Storage {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "testdb")

	stor, err := openNoFlockStorage(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stor.Close() })

	return stor
}
