package nb9

import (
	"context"
	"io"
	"io/fs"
)

type FS interface {
	// WithContext returns a new FS with the given context.
	WithContext(context.Context) FS

	// Open opens the named file.
	Open(name string) (fs.File, error)

	OpenWriter(name string) (io.WriteCloser, error)

	Stat(name string) (fs.FileInfo, error)

	ReadDir(name string) ([]fs.DirEntry, error)

	// NOTE: WalkDir allows us to do streaming. If dirEntry is a
	// RemoteFileInfo, we always populate the Text and Data fields so that we
	// can get the file contents while walking.
	//
	// What if we only want to stream a directory, not the entire file tree? No
	// choice, we need to use fs.SkipDir and whenever we receive fs.SkipDir,
	// set the ignorePrefix to the current directory and discard all names with
	// that prefix. So we can't stream a directory per se but we can stream the
	// entire tree and ignore any grandchildren of the current directory.
	WalkDir(root string, fn func(path string, d fs.DirEntry, err error) error)

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

// TODO: fileInfo.Sys().(*RemoteFileInfo)
// if *RemoteFileInfo, we can get the bytes directly without having to call Open
type FileInfo interface {
	fs.FileInfo
	Count() int64
	Bytes() string
}

type DirReader interface {
	ReadDir(batch []FileInfo) (n int, err error)
	Close() error
}
