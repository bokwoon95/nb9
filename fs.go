package nb9

import (
	"context"
	"io"
	"io/fs"
)

// IndexedFS

type FS interface {
	// WithContext returns a new FS with the given context.
	WithContext(context.Context) FS

	// Open opens the named file.
	Open(name string) (fs.File, error)

	OpenWriter(name string) (io.WriteCloser, error)

	Stat(name string) (fs.FileInfo, error)

	ReadDir(name string) ([]fs.DirEntry, error)

	// NOTE: For WalkDir, RemoteFS always fills in the Text and Data fields of
	// the RemoteFile. Only for WalkDir(), not for Stat() or ReadDir().
	WalkDir(root string, fn func(path string, d fs.DirEntry, err error) error)

	// NOTE: We will need to stat the parent directory first in order to get
	// the count, then we iterate the directory.
	// NOTE: IterateDir is a specialization of WalkDir. If IterateDir is not
	// implemented, we will just use WalkDir and fs.SkipDir together (less
	// efficient on a database).
	IterateDir(dir string, fn func(name string, d fs.DirEntry, err error) error)

	// Mkdir creates a new directory with the specified name.
	Mkdir(name string, perm fs.FileMode) error

	// Remove removes the named file or directory.
	Remove(name string) error

	// Rename renames (moves) oldname to newname. If newname already exists and
	// is not a directory, Rename replaces it.
	Rename(oldname, newname string) error
}

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
