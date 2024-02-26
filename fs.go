package nb9

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"sync"
)

// If a buffer's capacity exceeds this value, don't put it back in the pool
// because it's too expensive to keep it around in memory.
//
// From https://victoriametrics.com/blog/tsdb-performance-techniques-sync-pool/:
//
// "The maximum capacity of a cached pool is limited to 2^18 bytes as we’ve
// found that the RAM cost of storing buffers larger than this limit is not
// worth the savings of not recreating those buffers."
const maxPoolableBufferCapacity = 1 << 18

var bufPool = sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

type FS interface {
	// WithContext returns a new FS with the given context.
	WithContext(context.Context) FS

	// Open opens the named file.
	Open(name string) (fs.File, error)

	// OpenWriter opens an io.WriteCloser that represents an instance of a
	// file. The parent directory must exist. If the file doesn't exist, it
	// should be created. If the file exists, its should be truncated.
	OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error)

	ReadDir(name string) ([]fs.DirEntry, error)

	// Mkdir creates a new directory with the specified name.
	Mkdir(name string, perm fs.FileMode) error

	MkdirAll(name string, perm fs.FileMode) error

	// Remove removes the named file or directory.
	Remove(name string) error

	RemoveAll(name string) error

	// Rename renames (moves) oldName to newName. newName must not exist.
	Rename(oldName, newName string) error

	Copy(srcName, destName string) error
}

type FileType struct {
	Ext         string
	ContentType string
	IsGzippable bool
	IsObject    bool
}

var fileTypes = map[string]FileType{
	".html":  {Ext: ".html", ContentType: "text/html; charset=utf-8", IsGzippable: true},
	".css":   {Ext: ".css", ContentType: "text/css; charset=utf-8", IsGzippable: true},
	".js":    {Ext: ".js", ContentType: "text/javascript; charset=utf-8", IsGzippable: true},
	".md":    {Ext: ".md", ContentType: "text/markdown; charset=utf-8", IsGzippable: true},
	".txt":   {Ext: ".txt", ContentType: "text/plain; charset=utf-8", IsGzippable: true},
	".svg":   {Ext: ".svg", ContentType: "image/svg+xml", IsGzippable: true},
	".ico":   {Ext: ".ico", ContentType: "image/ico", IsGzippable: true},
	".jpeg":  {Ext: ".jpeg", ContentType: "image/jpeg", IsObject: true},
	".jpg":   {Ext: ".jpg", ContentType: "image/jpeg", IsObject: true},
	".png":   {Ext: ".png", ContentType: "image/png", IsObject: true},
	".webp":  {Ext: ".webp", ContentType: "image/webp", IsObject: true},
	".gif":   {Ext: ".gif", ContentType: "image/gif", IsObject: true},
	".eot":   {Ext: ".eot", ContentType: "font/eot", IsGzippable: true},
	".otf":   {Ext: ".otf", ContentType: "font/otf", IsGzippable: true},
	".ttf":   {Ext: ".ttf", ContentType: "font/ttf", IsGzippable: true},
	".woff":  {Ext: ".woff", ContentType: "font/woff"},
	".woff2": {Ext: ".woff2", ContentType: "font/woff2"},
	".atom":  {Ext: ".atom", ContentType: "application/atom+xml; charset=utf-8", IsGzippable: true},
	".json":  {Ext: ".json", ContentType: "application/json", IsGzippable: true},
}
