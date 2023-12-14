package nb9

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/bokwoon95/nb9/sq"
)

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

	// Mkdir creates a new directory with the specified name.
	Mkdir(dir string, perm fs.FileMode) error

	// Remove removes the named file or directory.
	Remove(name string) error

	// Rename renames (moves) oldname to newname. If newname already exists and
	// is not a directory, Rename replaces it.
	Rename(oldname, newname string) error

	// For RemoteFS, WalkDir should fetch the file contents as well.
	WalkDir(dir string, fn fs.WalkDirFunc) error

	// Extensions: ReadDirAfterName, ReadDirBeforeName, ReadDirAfterModTime, ReadDirBeforeModTime
	// For RemoteFS, ReadDir should fetch the file contents as well.
	// Nevertheless, if the file contents aren't fetched on ReadDir we can
	// still fetch it using FS.Open(). This specialization is not needed for
	// ReadDirAfterName, ReadDirBeforeName, ReadDirAfterModTime,
	// ReadDirBeforeModTime.
	ReadDir(dir string, fn fs.WalkDirFunc) error

	// ReadDirAfterName(dir string, fn fs.WalkDirFunc, name string, limit int) error
	// ReadDirBeforeName(dir string, fn fs.WalkDirFunc, name string, limit int) error
	// ReadDirAfterModTime(dir string, fn fs.WalkDirFunc, modTime time.Time, limit int) error
	// ReadDirBeforeModTime(dir string, fn fs.WalkDirFunc, modTime time.Time, limit int) error
}

// LocalFS represents a filesystem rooted on a local directory.
type LocalFS struct {
	// ctx provides the context of all operations called on the LocalFS.
	ctx context.Context

	// rootDir is the root directory of the LocalFS.
	rootDir string

	// tempDir is the temp directory of the LocalFS. Files are first written to
	// the tempDir before being swapped into the rootDir via an atomic rename
	// (windows is the exception I've found the renames there to be BUGGY AF!
	// *insert github issue where rename on windows keep failing intermittently
	// with an annoying permission error*)
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

// LocalFileWriter represents a writable file on a LocalFS.
type LocalFileWriter struct {
	// ctx provides the context of all operations called on the file.
	ctx context.Context

	// rootDir is the root directory that houses the destination file.
	rootDir string

	// name is the name of the destination file relative to rootDir.
	name string

	// tempFile is temporary file we are writing to first before we do an
	// atomic rename into the destination file. This ensures that parallel
	// writers do not corrupt the destination file, writes are always all or
	// nothing and the last writer wins.
	tempFile *os.File

	// tempDir is the temp directory that houses the temporary file.
	tempDir string

	// tempName is the name of the temporary file relative to tempDir. It is
	// randomly generated by os.CreateTemp.
	tempName string

	// writeFailed records if any writes to the tempFile failed.
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
	err = os.Rename(tempFilePath, destFilePath)
	if err != nil {
		return err
	}
	return nil
}

func (fsys *LocalFS) Mkdir(dir string, perm fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(dir) || strings.Contains(dir, "\\") {
		return &fs.PathError{Op: "mkdir", Path: dir, Err: fs.ErrInvalid}
	}
	dir = filepath.FromSlash(dir)
	return os.Mkdir(filepath.Join(fsys.rootDir, dir), perm)
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

func (fsys *LocalFS) WalkDir(name string, fn fs.WalkDirFunc) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "walkdir", Path: name, Err: fs.ErrInvalid}
	}
	return fs.WalkDir(os.DirFS(fsys.rootDir), name, fn)
}

func (fsys *LocalFS) ReadDir(name string, fn fs.WalkDirFunc) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	file, err := os.Open(filepath.Join(fsys.rootDir, name))
	if err != nil {
		return err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return fn(name, nil, err)
	}
	if !fileInfo.IsDir() {
		return &fs.PathError{Op: "readdir", Path: name, Err: syscall.ENOTDIR}
	}
	for {
		dirEntries, err := file.ReadDir(1000)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		for _, dirEntry := range dirEntries {
			err = fn(dirEntry.Name(), dirEntry, nil)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type RemoteFS struct {
	ctx       context.Context
	db        *sql.DB
	dialect   string
	errorCode func(error) string
	storage   Storage
}

func NewRemoteFS(dialect string, db *sql.DB, errorCode func(error) string, storage Storage) *RemoteFS {
	return &RemoteFS{
		ctx:       context.Background(),
		db:        db,
		dialect:   dialect,
		errorCode: errorCode,
		storage:   storage,
	}
}

// func (fsys *RemoteFS) WithContext(ctx context.Context) FS {
// 	return &RemoteFS{
// 		ctx:     ctx,
// 		db:      fsys.db,
// 		dialect: fsys.dialect,
// 		storage: fsys.storage,
// 	}
// }

func (fsys *RemoteFS) Stat(name string) (fs.FileInfo, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	return nil, nil
}

type RemoteFile struct {
	ctx        context.Context
	fileID     [16]byte
	parentID   [16]byte
	filePath   string
	isDir      bool
	count      int64
	size       int64
	modTime    time.Time
	perm       fs.FileMode
	buf        *bytes.Buffer
	readCloser io.ReadCloser
}

func (file *RemoteFile) Read(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		return 0, err
	}
	if file.isDir {
		return 0, &fs.PathError{Op: "read", Path: file.filePath, Err: syscall.EISDIR}
	}
	if file.buf != nil {
		return file.buf.Read(p)
	}
	return file.readCloser.Read(p)
}

func (file *RemoteFile) Close() error {
	if file.isDir {
		return nil
	}
	if file.buf != nil {
		return nil
	}
	return file.readCloser.Close()
}

func (file *RemoteFile) Name() string {
	return path.Base(file.filePath)
}

func (file *RemoteFile) Size() int64 {
	if file.buf != nil {
		return int64(file.buf.Len())
	}
	return file.size
}

func (file *RemoteFile) Mode() fs.FileMode {
	if file.isDir {
		return file.perm | fs.ModeDir
	}
	return file.perm &^ fs.ModeDir
}

func (file *RemoteFile) ModTime() time.Time { return file.modTime }

func (file *RemoteFile) IsDir() bool { return file.isDir }

func (file *RemoteFile) Sys() any { return &file }

func (file *RemoteFile) Type() fs.FileMode { return file.Mode().Type() }

func (file *RemoteFile) Info() (fs.FileInfo, error) { return file, nil }

func (fsys *RemoteFS) Stat(name string) (fs.FileInfo, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return &RemoteFile{filePath: ".", isDir: true}, nil
	}
	file, err := sq.FetchOne(fsys.ctx, fsys.db, sq.Query{
		Dialect: fsys.dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) (file RemoteFile) {
		row.UUID(&file.fileID, "file_id")
		row.UUID(&file.parentID, "parent_id")
		file.filePath = row.String("file_path")
		file.isDir = row.Bool("is_dir")
		file.count = row.Int64("count")
		file.size = row.Int64("{}", sq.DialectExpression{
			Default: sq.Expr("SUM(COALESCE(OCTET_LENGTH(text), OCTET_LENGTH(data), size, 0))"),
			Cases: []sq.DialectCase{{
				Dialect: "sqlite",
				Result:  sq.Expr("SUM(COALESCE(LENGTH(CAST(text AS BLOB)), LENGTH(CAST(data AS BLOB)), size, 0))"),
			}},
		})
		file.modTime = row.Time("mod_time")
		file.perm = fs.FileMode(row.Int("perm"))
		return file
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	file.ctx = fsys.ctx
	return &file, nil
}

var textExtensions = map[string]bool{
	".html": true,
	".css":  true,
	".js":   true,
	".md":   true,
	".txt":  true,
	".json": true,
	".xml":  true,
}

func isFulltextIndexed(filePath string) bool {
	ext := path.Ext(filePath)
	head, tail, _ := strings.Cut(filePath, "/")
	switch head {
	case "notes":
		return ext == ".html" || ext == ".css" || ext == ".js" || ext == ".md" || ext == ".txt"
	case "pages":
		return ext == ".html"
	case "posts":
		return ext == ".md"
	case "output":
		next, _, _ := strings.Cut(tail, "/")
		switch next {
		case "posts":
			return false
		case "themes":
			return ext == ".html" || ext == ".css" || ext == ".js" || ext == ".md" || ext == ".txt"
		default:
			return ext == ".css" || ext == ".js" || ext == ".md"
		}
	}
	return false
}

func (fsys *RemoteFS) Open(name string) (fs.File, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return &RemoteFile{filePath: ".", isDir: true}, nil
	}
	file, err := sq.FetchOne(fsys.ctx, fsys.db, sq.Query{
		Dialect: fsys.dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) (file RemoteFile) {
		row.UUID(&file.fileID, "file_id")
		row.UUID(&file.parentID, "parent_id")
		file.filePath = row.String("file_path")
		file.isDir = row.Bool("is_dir")
		file.count = row.Int64("count")
		file.size = row.Int64("{}", sq.DialectExpression{
			Default: sq.Expr("SUM(COALESCE(OCTET_LENGTH(text), OCTET_LENGTH(data), size, 0))"),
			Cases: []sq.DialectCase{{
				Dialect: "sqlite",
				Result:  sq.Expr("SUM(COALESCE(LENGTH(CAST(text AS BLOB)), LENGTH(CAST(data AS BLOB)), size, 0))"),
			}},
		})
		file.modTime = row.Time("mod_time")
		file.perm = fs.FileMode(row.Int("perm"))
		b := row.Bytes("COALESCE(text, data)")
		if b != nil {
			file.buf = bytes.NewBuffer(b)
		}
		return file
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	if !file.isDir {
		if !textExtensions[path.Ext(file.filePath)] {
			file.readCloser, err = fsys.storage.Get(context.Background(), hex.EncodeToString(file.fileID[:])+path.Ext(file.filePath))
			if err != nil {
				return nil, err
			}
		}
	}
	return &file, nil
}

type RemoteFileWriter struct {
	ctx            context.Context
	db             *sql.DB
	dialect        string
	storage        Storage
	fileID         [16]byte
	parentID       any // either nil or [16]byte
	filePath       string
	perm           fs.FileMode
	buf            *bytes.Buffer
	modTime        time.Time
	storageWriter  *io.PipeWriter
	storageWritten int
	storageResult  chan error
	writeFailed    bool
}

func (fsys *RemoteFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
	}
	file := &RemoteFileWriter{
		ctx:      fsys.ctx,
		db:       fsys.db,
		dialect:  fsys.dialect,
		storage:  fsys.storage,
		filePath: name,
		perm:     perm,
		modTime:  time.Now().UTC().Truncate(time.Second),
	}
	parentDir := path.Dir(file.filePath)
	if parentDir != "." {
		results, err := sq.FetchAll(fsys.ctx, fsys.db, sq.Query{
			Dialect: fsys.dialect,
			Format:  "SELECT {*} FROM files WHERE file_path IN ({parentDir}, {filePath})",
			Values: []any{
				sq.StringParam("parentDir", parentDir),
				sq.StringParam("filePath", file.filePath),
			},
		}, func(row *sq.Row) (result struct {
			fileID   [16]byte
			filePath string
			isDir    bool
		}) {
			row.UUID(&result.fileID, "file_id")
			result.filePath = row.String("file_path")
			result.isDir = row.Bool("is_dir")
			return result
		})
		if err != nil {
			return nil, err
		}
		for _, result := range results {
			switch result.filePath {
			case name:
				if result.isDir {
					return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
				}
				file.fileID = result.fileID
			case parentDir:
				if !result.isDir {
					return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.ENOTDIR}
				}
				file.parentID = result.fileID
			}
		}
		if file.parentID == nil {
			return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrNotExist}
		}
	} else {
		result, err := sq.FetchOne(fsys.ctx, fsys.db, sq.Query{
			Dialect: fsys.dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("filePath", file.filePath),
			},
		}, func(row *sq.Row) (result struct {
			fileID   [16]byte
			filePath string
			isDir    bool
		}) {
			row.UUID(&result.fileID, "file_id")
			result.filePath = row.String("file_path")
			result.isDir = row.Bool("is_dir")
			return result
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrNotExist}
			}
			return nil, err
		}
		if result.isDir {
			return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
		}
	}
	if textExtensions[path.Ext(file.filePath)] {
		file.buf = bufPool.Get().(*bytes.Buffer)
		file.buf.Reset()
	} else {
		pipeReader, pipeWriter := io.Pipe()
		file.storageWriter = pipeWriter
		file.storageResult = make(chan error, 1)
		go func() {
			file.storageResult <- fsys.storage.Put(file.ctx, hex.EncodeToString(file.fileID[:])+path.Ext(file.filePath), pipeReader)
			close(file.storageResult)
		}()
	}
	return file, nil
}

func (file *RemoteFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	if textExtensions[path.Ext(file.filePath)] {
		n, err = file.buf.Write(p)
		if err != nil {
			file.writeFailed = true
		}
		return n, err
	}
	n, err = file.storageWriter.Write(p)
	file.storageWritten += n
	if err != nil {
		file.writeFailed = true
	}
	return n, err
}

func (file *RemoteFileWriter) Close() error {
	if textExtensions[path.Ext(file.filePath)] {
		defer bufPool.Put(file.buf)
	} else {
		file.storageWriter.Close()
		err := <-file.storageResult
		if err != nil {
			return err
		}
	}
	if file.writeFailed {
		return nil
	}

	// If file exists, just have to update the file entry in the database.
	if file.fileID != [16]byte{} {
		if textExtensions[path.Ext(file.filePath)] {
			if isFulltextIndexed(file.filePath) {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = {text}, data = NULL, size = NULL, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("text", file.buf.Bytes()),
						sq.Param("modTime", sq.Timestamp{Time: file.modTime, Valid: true}),
						sq.UUIDParam("fileID", file.fileID),
					},
				})
				if err != nil {
					return err
				}
			} else {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = NULL, data = {data}, size = NULL, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("data", file.buf.Bytes()),
						sq.Param("modTime", sq.Timestamp{Time: file.modTime, Valid: true}),
						sq.UUIDParam("fileID", file.fileID),
					},
				})
				if err != nil {
					return err
				}
			}
		} else {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format:  "UPDATE files SET text = NULL, data = NULL, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
				Values: []any{
					sq.IntParam("size", file.storageWritten),
					sq.Param("modTime", sq.Timestamp{Time: file.modTime, Valid: true}),
					sq.UUIDParam("fileID", file.fileID),
				},
			})
			if err != nil {
				return err
			}
		}
		return nil
	}

	// If we reach here it means file doesn't exist. Insert a new file entry
	// into the database.
	if textExtensions[path.Ext(file.filePath)] {
		if isFulltextIndexed(file.filePath) {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, is_dir, text, mod_time, perm)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {isDir}, {text}, {modTime}, {perm})",
				Values: []any{
					sq.UUIDParam("fileID", NewID()),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.BoolParam("isDir", false),
					sq.BytesParam("text", file.buf.Bytes()),
					sq.Param("modTime", sq.Timestamp{Time: file.modTime, Valid: true}),
					sq.Param("perm", file.perm),
				},
			})
			if err != nil {
				return err
			}
		} else {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, is_dir, data, mod_time, perm)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {isDir}, {data}, {modTime}, {perm})",
				Values: []any{
					sq.UUIDParam("fileID", NewID()),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.BoolParam("isDir", false),
					sq.BytesParam("data", file.buf.Bytes()),
					sq.Param("modTime", sq.Timestamp{Time: file.modTime, Valid: true}),
					sq.Param("perm", file.perm),
				},
			})
			if err != nil {
				return err
			}
		}
	} else {
		_, err := sq.Exec(file.ctx, file.db, sq.Query{
			Dialect: file.dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, is_dir, size, mod_time, perm)" +
				" VALUES ({fileID}, {parentID}, {filePath}, {isDir}, {size}, {modTime}, {perm})",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.UUIDParam("parentID", file.parentID),
				sq.StringParam("filePath", file.filePath),
				sq.BoolParam("isDir", false),
				sq.IntParam("size", file.storageWritten),
				sq.Param("modTime", sq.Timestamp{Time: file.modTime, Valid: true}),
				sq.Param("perm", file.perm),
			},
		})
		if err != nil {
			go file.storage.Delete(context.Background(), hex.EncodeToString(file.fileID[:])+path.Ext(file.filePath))
			return err
		}
	}
	return nil
}

func (fsys *RemoteFS) ReadDir(name string) ([]fs.DirEntry, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	// Special case: if name is ".", ReadDir returns all top-level files in
	// the root directory (identified by a NULL parent_id).
	if name == "." {
		dirEntries, err := sq.FetchAll(fsys.ctx, fsys.db, sq.Query{
			Dialect: fsys.dialect,
			Format:  "SELECT {*} FROM files WHERE parent_id IS NULL ORDER BY file_path",
			Values: []any{
				sq.StringParam("name", name),
			},
		}, func(row *sq.Row) fs.DirEntry {
			var file RemoteFile
			row.UUID(&file.fileID, "file_id")
			file.filePath = row.String("file_path")
			file.isDir = row.Bool("is_dir")
			file.size = row.Int64("size")
			file.modTime = row.Time("mod_time")
			file.perm = fs.FileMode(row.Int("perm"))
			return &file
		})
		if err != nil {
			return nil, err
		}
		return dirEntries, nil
	}
	cursor, err := sq.FetchCursor(fsys.ctx, fsys.db, sq.Query{
		Dialect: fsys.dialect,
		Format: "SELECT {*}" +
			" FROM files AS parent" +
			" LEFT JOIN files AS child ON child.parent_id = parent.file_id" +
			" WHERE parent.file_path = {name}" +
			" ORDER BY child.file_path",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) (result struct {
		RemoteFile
		ParentIsDir bool
	}) {
		row.UUID(&result.fileID, "child.file_id")
		row.UUID(&result.parentID, "child.parent_id")
		result.filePath = row.String("child.file_path")
		result.isDir = row.Bool("child.is_dir")
		result.size = row.Int64("child.size")
		result.modTime = row.Time("child.mod_time")
		result.perm = fs.FileMode(row.Int("child.perm"))
		result.ParentIsDir = row.Bool("parent.is_dir")
		return result
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var dirEntries []fs.DirEntry
	for cursor.Next() {
		result, err := cursor.Result()
		if err != nil {
			return nil, err
		}
		if !result.ParentIsDir {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: syscall.ENOTDIR}
		}
		// file_id is a primary key, it must always exist. If it doesn't exist,
		// it means the left join failed to match any child entries i.e. the
		// directory is empty, so we return no entries.
		if result.fileID == [16]byte{} {
			return nil, cursor.Close()
		}
		dirEntries = append(dirEntries, &result.RemoteFile)
	}
	if len(dirEntries) == 0 {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	return dirEntries, cursor.Close()
}

type Storage interface {
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Put(ctx context.Context, key string, reader io.Reader) error
	Delete(ctx context.Context, key string) error
}

type S3Storage struct {
	Client *s3.Client
	Bucket string
}

var _ Storage = (*S3Storage)(nil)

type S3StorageConfig struct {
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	Bucket          string `json:"bucket,omitempty"`
	AccessKeyID     string `json:"accessKeyID,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
}

func NewS3Storage(ctx context.Context, config S3StorageConfig) (*S3Storage, error) {
	storage := &S3Storage{
		Client: s3.New(s3.Options{
			BaseEndpoint: aws.String(config.Endpoint),
			Region:       config.Region,
			Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(config.AccessKeyID, config.SecretAccessKey, "")),
		}),
		Bucket: config.Bucket,
	}
	// Ping the bucket and see if we have access.
	_, err := storage.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  &storage.Bucket,
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return nil, err
	}
	return storage, nil
}

func (storage *S3Storage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	output, err := storage.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "NoSuchKey" {
				return nil, &fs.PathError{Op: "open", Path: key, Err: fs.ErrNotExist}
			}
		}
		return nil, err
	}
	return output.Body, nil
}

func (storage *S3Storage) Put(ctx context.Context, key string, reader io.Reader) error {
	_, err := storage.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
		Body:   reader,
	})
	if err != nil {
		return err
	}
	return nil
}

func (storage *S3Storage) Delete(ctx context.Context, key string) error {
	_, err := storage.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	return nil
}

type InMemoryStorage struct {
	mu      sync.RWMutex
	entries map[string][]byte
}

var _ Storage = (*InMemoryStorage)(nil)

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		mu:      sync.RWMutex{},
		entries: make(map[string][]byte),
	}
}

func (storage *InMemoryStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	storage.mu.RLock()
	value, ok := storage.entries[key]
	storage.mu.RUnlock()
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: key, Err: fs.ErrNotExist}
	}
	return io.NopCloser(bytes.NewReader(value)), nil
}

func (storage *InMemoryStorage) Put(ctx context.Context, key string, reader io.Reader) error {
	value, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	storage.mu.Lock()
	storage.entries[key] = value
	storage.mu.Unlock()
	return nil
}

func (storage *InMemoryStorage) Delete(ctx context.Context, key string) error {
	storage.mu.Lock()
	delete(storage.entries, key)
	storage.mu.Unlock()
	return nil
}

type FileStorage struct {
	rootDir string
	tempDir string
}

func NewFileStorage(rootDir, tempDir string) *FileStorage {
	return &FileStorage{
		rootDir: filepath.FromSlash(rootDir),
		tempDir: filepath.FromSlash(tempDir),
	}
}

func (storage *FileStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	err := ctx.Err()
	if err != nil {
		return nil, err
	}
	if len(key) < 4 {
		return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrInvalid}
	}
	file, err := os.Open(filepath.Join(storage.rootDir, key[:4], key))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &fs.PathError{Op: "open", Path: key, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	return file, nil
}

func (storage *FileStorage) Put(ctx context.Context, key string, reader io.Reader) error {
	err := ctx.Err()
	if err != nil {
		return err
	}
	if len(key) < 4 {
		return &fs.PathError{Op: "put", Path: key, Err: fs.ErrInvalid}
	}
	if runtime.GOOS == "windows" {
		file, err := os.OpenFile(filepath.Join(storage.rootDir, key[:4], key), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		_, err = io.Copy(file, reader)
		if err != nil {
			return err
		}
		return nil
	}
	tempDir := storage.tempDir
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	tempFile, err := os.CreateTemp(tempDir, "__notebrewtemp*__")
	if err != nil {
		return err
	}
	fileInfo, err := tempFile.Stat()
	if err != nil {
		return err
	}
	tempFilePath := filepath.Join(tempDir, fileInfo.Name())
	destFilePath := filepath.Join(storage.rootDir, key[:4], key)
	defer os.Remove(tempFilePath)
	defer tempFile.Close()
	_, err = io.Copy(tempFile, reader)
	if err != nil {
		return err
	}
	err = tempFile.Close()
	if err != nil {
		return err
	}
	err = os.Rename(tempFilePath, destFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		err := os.Mkdir(filepath.Join(storage.rootDir, key[:4]), 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		err = os.Rename(tempFilePath, destFilePath)
		if err != nil {
			return err
		}
	}
	return nil
}

func (storage *FileStorage) Delete(ctx context.Context, key string) error {
	err := ctx.Err()
	if err != nil {
		return err
	}
	if len(key) < 4 {
		return &fs.PathError{Op: "put", Path: key, Err: fs.ErrInvalid}
	}
	err = os.Remove(filepath.Join(storage.rootDir, key[:4], key))
	if err != nil {
		return err
	}
	return nil
}

func NewID() [16]byte {
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
	var id [16]byte
	copy(id[:5], timestamp[len(timestamp)-5:])
	_, err := rand.Read(id[5:])
	if err != nil {
		panic(err)
	}
	return id
}

func IsKeyViolation(dialect string, errcode string) bool {
	switch dialect {
	case "sqlite":
		return errcode == "1555" || errcode == "2067" // SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE
	case "postgres":
		return errcode == "23505" // unique_violation
	case "mysql":
		return errcode == "1062" // ER_DUP_ENTRY
	case "sqlserver":
		return errcode == "2627"
	default:
		return false
	}
}

func IsForeignKeyViolation(dialect string, errcode string) bool {
	switch dialect {
	case "sqlite":
		return errcode == "787" //  SQLITE_CONSTRAINT_FOREIGNKEY
	case "postgres":
		return errcode == "23503" // foreign_key_violation
	case "mysql":
		return errcode == "1216" // ER_NO_REFERENCED_ROW
	case "sqlserver":
		return errcode == "547"
	default:
		return false
	}
}
