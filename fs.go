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
	// - fs.ErrInvalid
	// - fs.ErrNotExist
	// - syscall.EISDIR (read file)

	// OpenWriter opens an io.WriteCloser that represents an instance of a
	// file. The parent directory must exist. If the file doesn't exist, it
	// should be created. If the file exists, its should be truncated.
	OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error)
	// - fs.ErrInvalid
	// - syscall.EISDIR
	// - syscall.ENOTDIR (parent)
	// - fs.ErrNotExist (parent)

	// ReadDir reads the named directory and returns a list of directory
	// entries sorted by filename.
	ReadDir(name string) ([]fs.DirEntry, error)
	// - fs.ErrInvalid
	// - fs.ErrNotExist
	// - syscall.ENOTDIR

	// Mkdir creates a new directory with the specified name.
	Mkdir(name string, perm fs.FileMode) error
	// - fs.ErrInvalid
	// - fs.ErrNotExist (parent)
	// - fs.ErrExist

	// Remove removes the named file or directory.
	Remove(name string) error
	// - fs.ErrInvalid
	// - fs.ErrNotExist (parent)
	// - syscall.ENOTEMPTY

	// Rename renames (moves) oldname to newname. If newname already exists and
	// is not a directory, Rename replaces it.
	Rename(oldname, newname string) error
	// - fs.ErrInvalid
	// - fs.ErrNotExist (oldname)
	// - syscall.EISDIR (newname)
}

type File interface {
}
