package nb9

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// IndexedFS

type FS interface {
	// WithContext returns a new FS with the given context.
	WithContext(context.Context) FS

	// Open opens the named file.
	Open(name string) (fs.File, error)

	// OpenWriter opens an io.WriteCloser that represents an instance of a
	// file. The parent directory must exist. If the file doesn't exist, it
	// should be created. If the file exists, its should be truncated.
	OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error)

	// ReadDir reads the named directory and returns a list of directory
	// entries sorted by filename.
	ReadDir(name string) ([]fs.DirEntry, error)

	// Mkdir creates a new directory with the specified name.
	Mkdir(name string, perm fs.FileMode) error

	// Remove removes the named file or directory.
	Remove(name string) error

	// Rename renames (moves) oldname to newname. If newname already exists and
	// is not a directory, Rename replaces it.
	Rename(oldname, newname string) error
}

type LocalFS struct {
	ctx     context.Context
	rootDir string
	tempDir string
}

func NewLocalFS(rootDir, tempDir string) *LocalFS {
	return &LocalFS{
		ctx:     context.Background(),
		rootDir: filepath.FromSlash(rootDir),
		tempDir: filepath.FromSlash(tempDir),
	}
}

func (fsys *LocalFS) WithContext(ctx context.Context) FS {
	return &LocalFS{
		ctx:     ctx,
		rootDir: fsys.rootDir,
		tempDir: fsys.tempDir,
	}
}

func (fsys *LocalFS) Stat(name string) (fs.FileInfo, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.Stat(filepath.Join(fsys.rootDir, name))
}

func (fsys *LocalFS) Open(name string) (fs.File, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	file, err := os.Open(filepath.Join(fsys.rootDir, name))
	if err != nil {
		return nil, err
	}
	return file, nil
}

type LocalFileWriter struct {
	ctx         context.Context
	rootDir     string
	tempDir     string
	name        string
	perm        fs.FileMode
	tempFile    *os.File
	tempName    string
	writeFailed bool
}

func (file *LocalFileWriter) ReadFrom(r io.Reader) (n int64, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	n, err = file.tempFile.ReadFrom(r)
	if err != nil {
		file.writeFailed = true
		return n, err
	}
	return n, nil
}

func (file *LocalFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	n, err = file.tempFile.Write(p)
	if err != nil {
		file.writeFailed = true
		return n, err
	}
	return n, nil
}

func (file *LocalFileWriter) Close() error {
	tempFilePath := filepath.Join(file.tempDir, file.tempName)
	destFilePath := filepath.Join(file.rootDir, file.name)
	defer os.Remove(tempFilePath)
	err := file.tempFile.Close()
	if err != nil {
		return err
	}
	if file.writeFailed {
		return nil
	}
	_, err = os.Stat(destFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		defer os.Chmod(destFilePath, file.perm)
	}
	err = os.Rename(tempFilePath, destFilePath)
	if err != nil {
		return err
	}
	return nil
}

func (fsys *LocalFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	if runtime.GOOS == "windows" {
		file, err := os.OpenFile(filepath.Join(fsys.rootDir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return nil, err
		}
		return file, nil
	}
	file := &LocalFileWriter{
		ctx:     fsys.ctx,
		rootDir: fsys.rootDir,
		tempDir: fsys.tempDir,
		name:    filepath.FromSlash(name),
		perm:    perm,
	}
	if file.tempDir == "" {
		file.tempDir = os.TempDir()
	}
	file.tempFile, err = os.CreateTemp(file.tempDir, "__notebrewtemp*__")
	if err != nil {
		return nil, err
	}
	fileInfo, err := file.tempFile.Stat()
	if err != nil {
		return nil, err
	}
	file.tempName = fileInfo.Name()
	return file, nil
}

func (fsys *LocalFS) ReadDir(name string) ([]fs.DirEntry, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.ReadDir(filepath.Join(fsys.rootDir, name))
}

func (fsys *LocalFS) Mkdir(name string, perm fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.Mkdir(filepath.Join(fsys.rootDir, name), perm)
}

func (fsys *LocalFS) MkdirAll(name string, perm fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdirall", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.MkdirAll(filepath.Join(fsys.rootDir, name), perm)
}

func (fsys *LocalFS) Remove(name string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.Remove(filepath.Join(fsys.rootDir, name))
}

func (fsys *LocalFS) RemoveAll(name string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "removeall", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.RemoveAll(filepath.Join(fsys.rootDir, name))
}

func (fsys *LocalFS) Rename(oldname, newname string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(oldname) || strings.Contains(oldname, "\\") {
		return &fs.PathError{Op: "rename", Path: oldname, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newname) || strings.Contains(newname, "\\") {
		return &fs.PathError{Op: "rename", Path: newname, Err: fs.ErrInvalid}
	}
	oldname = filepath.FromSlash(oldname)
	newname = filepath.FromSlash(newname)
	return os.Rename(filepath.Join(fsys.rootDir, oldname), filepath.Join(fsys.rootDir, newname))
}

// TODO: RemoteFS implements WalkDir (fallback: fs.WalkDir).
// - WalkDir must fetch the file info as well (fallback: FS.Open).
// TODO: RemoteFS implements IterateDir, IterateDirAfterName, IterateDirBeforeName, IterateDirAfterModTime, IterateDirBeforeModTime (fallback: ReadDir).
// - IterateDir must fetch the file info as well (fallback: FS.Open).

// NOTE: we will call these inline, without exporting a public (or private)
// interface.
// NOTE: ReadDirAfterName/ReadDirBeforeName is just a specialization of
// ReadDir. If unimplemented, we will just use ReadDir (less efficient).
type NameIndexedFS interface {
	ReadDirAfterName(dir string, name string, limit int) ([]fs.DirEntry, error)
	ReadDirBeforeName(dir string, name string, limit int) ([]fs.DirEntry, error)
}

// NOTE: we will call these inline, without exporting a public (or private)
// interface.
// NOTE: ReadDirAfterModTime/ReadDirBeforeModTime is just a specialization of
// ReadDir. If unimplemented, we will just use ReadDir (less efficient).
type ModTimeIndexedFS interface {
	ReadDirBeforeModTime(dir string, modTime string, limit int) ([]fs.DirEntry, error)
	ReadDirAfterModTime(dir string, modTime string, limit int) ([]fs.DirEntry, error)
}

// Limit
// BeforeName
// AfterName
// BeforeModTime
// FilterByName
// FilterByModTime
// WalkDirBeforeName(root string, fn fs.WalkDirFunc, before, after string, limit int)

// NOTE: what if you want to read a directory without opening a file, which
// incurs a database lookup? Should (*RemoteFile).Read be lazily intialized? FS.OpenFile should be as cheap as possible?
type File interface {
	Stat() (FileInfo, error)
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	NameFilter(before, after string, limit int) error
	ReadDirList(batch []FileInfo) (n int, err error)
	ReadDirTree(batch []FileInfo) (n int, err error)
	// FilterByName(before, after string, limit int) // For sorting and filtering, optional and discoverable
	// FilterByModificationTime(before, after time.Time, limit int) // For sorting and filtering, optional and discoverable
	// ReadDirList([]DirEntry) (n int, err error) // For streaming
	// ReadDirTree([]DirEntry) (n int, err error)
}

// TODO: fileInfo.Sys().(*RemoteFileInfo)
// if *RemoteFileInfo, we can get the bytes directly without having to call Open
type FileInfo interface {
	fs.FileInfo
	Count() int64
	Bytes() string
}
