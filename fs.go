package nb9

import (
	"context"
	"io/fs"
	"time"
)

type FS interface {
	// WithContext returns a new FS with the given context.
	WithContext(context.Context) FS

	// Open opens the named file.
	Open(name string) (fs.File, error)

	Stat(name string) (FileInfo, error)

	// Mkdir creates a new directory with the specified name.
	Mkdir(name string, perm fs.FileMode) error

	// Remove removes the named file or directory.
	Remove(name string) error

	// Rename renames (moves) oldname to newname. If newname already exists and
	// is not a directory, Rename replaces it.
	Rename(oldname, newname string) error
}

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

type FileInfo interface {
	Name() string
	Size() int64
	Mode() fs.FileMode
	ModTime() time.Time
	IsDir() bool
	Open() (fs.File, error)
	Count() int64
}

type DirReader interface {
	ReadDir(batch []FileInfo) (n int, err error)
	Close() error
}
