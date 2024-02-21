package nb9

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/bokwoon95/nb9/sq"
)

type RemoteFSConfig struct {
	FilesDB        *sql.DB
	FilesDialect   string
	FilesErrorCode func(error) string
	Storage        Storage
	UsersDB        *sql.DB
	UsersDialect   string
	Logger         *slog.Logger
}

type RemoteFS struct {
	ctx            context.Context
	filesDB        *sql.DB
	filesDialect   string
	filesErrorCode func(error) string
	storage        Storage
	usersDB        *sql.DB
	usersDialect   string
	logger         *slog.Logger
}

func NewRemoteFS(config RemoteFSConfig) *RemoteFS {
	return &RemoteFS{
		ctx:            context.Background(),
		filesDB:        config.FilesDB,
		filesDialect:   config.FilesDialect,
		filesErrorCode: config.FilesErrorCode,
		storage:        config.Storage,
		usersDB:        config.UsersDB,
		usersDialect:   config.UsersDialect,
		logger:         config.Logger,
	}
}

func (fsys *RemoteFS) WithContext(ctx context.Context) FS {
	return &RemoteFS{
		ctx:          ctx,
		filesDB:      fsys.filesDB,
		filesDialect: fsys.filesDialect,
		storage:      fsys.storage,
		usersDB:      fsys.usersDB,
		usersDialect: fsys.usersDialect,
		logger:       fsys.logger,
	}
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
		file := &RemoteFile{
			ctx:     fsys.ctx,
			storage: fsys.storage,
			info:    &RemoteFileInfo{FilePath: ".", isDir: true},
		}
		return file, nil
	}
	var fileType FileType
	if ext := path.Ext(name); ext != "" {
		fileType = fileTypes[ext]
	}
	file, err := sq.FetchOne(fsys.ctx, fsys.filesDB, sq.Query{
		Dialect: fsys.filesDialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) *RemoteFile {
		file := &RemoteFile{
			ctx:      fsys.ctx,
			fileType: fileType,
			storage:  fsys.storage,
			info:     &RemoteFileInfo{},
		}
		file.info.FileID = row.UUID("file_id")
		file.info.FilePath = row.String("file_path")
		file.info.isDir = row.Bool("is_dir")
		file.info.size = row.Int64("size")
		file.info.modTime = row.Time("mod_time")
		file.info.CreationTime = row.Time("creation_time")
		if !fileType.IsObject {
			file.buf = bytes.NewBuffer(row.Bytes(bufPool.Get().(*bytes.Buffer).Bytes(), "COALESCE(text, data)"))
		}
		return file
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	file.isFulltextIndexed = isFulltextIndexed(file.info.FilePath)
	if fileType.IsObject {
		file.readCloser, err = file.storage.Get(file.ctx, encodeUUID(file.info.FileID)+path.Ext(file.info.FilePath))
		if err != nil {
			return nil, err
		}
		if file, ok := file.readCloser.(fs.File); ok {
			return file, nil
		}
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			// Do NOT pass file.buf directly to gzip.Reader or it will do an
			// unwanted read from the buffer! We want to keep file.buf unread
			// in case someone wants to reach directly into it and pulled out
			// the raw gzipped bytes.
			r := bytes.NewReader(file.buf.Bytes())
			file.gzipReader, _ = gzipReaderPool.Get().(*gzip.Reader)
			if file.gzipReader != nil {
				err = file.gzipReader.Reset(r)
				if err != nil {
					return nil, err
				}
			} else {
				file.gzipReader, err = gzip.NewReader(r)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return file, nil
}

func (fsys *RemoteFS) Stat(name string) (fs.FileInfo, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return &RemoteFileInfo{FilePath: ".", isDir: true}, nil
	}
	fileInfo, err := sq.FetchOne(fsys.ctx, fsys.filesDB, sq.Query{
		Dialect: fsys.filesDialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) *RemoteFileInfo {
		fileInfo := &RemoteFileInfo{}
		fileInfo.FileID = row.UUID("file_id")
		fileInfo.FilePath = row.String("file_path")
		fileInfo.isDir = row.Bool("is_dir")
		fileInfo.size = row.Int64("size")
		fileInfo.modTime = row.Time("mod_time")
		fileInfo.CreationTime = row.Time("creation_time")
		return fileInfo
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	return fileInfo, nil
}

type RemoteFileInfo struct {
	FileID       [16]byte
	FilePath     string
	isDir        bool
	size         int64
	modTime      time.Time
	CreationTime time.Time
}

func (fileInfo *RemoteFileInfo) Name() string { return path.Base(fileInfo.FilePath) }

func (fileInfo *RemoteFileInfo) Size() int64 { return fileInfo.size }

func (fileInfo *RemoteFileInfo) ModTime() time.Time { return fileInfo.modTime }

func (fileInfo *RemoteFileInfo) IsDir() bool { return fileInfo.isDir }

func (fileInfo *RemoteFileInfo) Sys() any { return nil }

func (fileInfo *RemoteFileInfo) Type() fs.FileMode { return fileInfo.Mode().Type() }

func (fileInfo *RemoteFileInfo) Info() (fs.FileInfo, error) { return fileInfo, nil }

func (fileInfo *RemoteFileInfo) Mode() fs.FileMode {
	if fileInfo.isDir {
		return fs.ModeDir
	}
	return 0
}

type RemoteFile struct {
	ctx               context.Context
	fileType          FileType
	isFulltextIndexed bool
	storage           Storage
	info              *RemoteFileInfo
	buf               *bytes.Buffer
	gzipReader        *gzip.Reader
	readCloser        io.ReadCloser
}

func (file *RemoteFile) Stat() (fs.FileInfo, error) {
	return file.info, nil
}

func (file *RemoteFile) Read(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		return 0, err
	}
	if file.info.isDir {
		return 0, &fs.PathError{Op: "read", Path: file.info.FilePath, Err: syscall.EISDIR}
	}
	if file.fileType.IsObject {
		return file.readCloser.Read(p)
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			return file.gzipReader.Read(p)
		} else {
			return file.buf.Read(p)
		}
	}
}

type emptyReader struct{}

var empty = (*emptyReader)(nil)

func (empty *emptyReader) Read(p []byte) (n int, err error) { return 0, io.EOF }

func (file *RemoteFile) Close() error {
	if file.info.isDir {
		return nil
	}
	if file.fileType.IsObject {
		if file.readCloser == nil {
			return fs.ErrClosed
		}
		err := file.readCloser.Close()
		if err != nil {
			return err
		}
		file.readCloser = nil
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			if file.gzipReader == nil {
				return fs.ErrClosed
			}
			file.gzipReader.Reset(empty)
			gzipReaderPool.Put(file.gzipReader)
			file.gzipReader = nil
			if file.buf.Cap() <= maxPoolableBufferCapacity {
				file.buf.Reset()
				bufPool.Put(file.buf)
			}
			file.buf = nil
		} else {
			if file.buf == nil {
				return fs.ErrClosed
			}
			if file.buf.Cap() <= maxPoolableBufferCapacity {
				file.buf.Reset()
				bufPool.Put(file.buf)
			}
			file.buf = nil
		}
	}
	return nil
}

func (fsys *RemoteFS) OpenWriter(name string, _ fs.FileMode) (io.WriteCloser, error) {
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
	var fileType FileType
	if ext := path.Ext(name); ext != "" {
		fileType = fileTypes[ext]
	}
	file := &RemoteFileWriter{
		ctx:               fsys.ctx,
		fileType:          fileType,
		isFulltextIndexed: isFulltextIndexed(name),
		db:                fsys.filesDB,
		dialect:           fsys.filesDialect,
		storage:           fsys.storage,
		filePath:          name,
		modTime:           time.Now().UTC(),
	}
	// If parentDir is the root directory, just fetch the file information.
	// Otherwise fetch both the parent and file information.
	parentDir := path.Dir(file.filePath)
	if parentDir == "." {
		result, err := sq.FetchOne(fsys.ctx, fsys.filesDB, sq.Query{
			Dialect: fsys.filesDialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("filePath", file.filePath),
			},
		}, func(row *sq.Row) (result struct {
			fileID [16]byte
			isDir  bool
		}) {
			result.fileID = row.UUID("file_id")
			result.isDir = row.Bool("is_dir")
			return result
		})
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
		} else {
			if result.isDir {
				return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
			}
			file.fileID = result.fileID
		}
	} else {
		results, err := sq.FetchAll(fsys.ctx, fsys.filesDB, sq.Query{
			Dialect: fsys.filesDialect,
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
			result.fileID = row.UUID("file_id")
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
		if file.parentID == [16]byte{} {
			return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrNotExist}
		}
	}
	if file.fileID == [16]byte{} {
		file.fileID = NewID()
	} else {
		file.exists = true
	}
	if fileType.IsObject {
		pipeReader, pipeWriter := io.Pipe()
		file.storageWriter = pipeWriter
		file.storageResult = make(chan error, 1)
		go func() {
			file.storageResult <- fsys.storage.Put(file.ctx, encodeUUID(file.fileID)+path.Ext(file.filePath), pipeReader)
			close(file.storageResult)
		}()
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			file.buf = bufPool.Get().(*bytes.Buffer)
			file.gzipWriter = gzipWriterPool.Get().(*gzip.Writer)
			file.gzipWriter.Reset(file.buf)
		} else {
			file.buf = bufPool.Get().(*bytes.Buffer)
		}
	}
	return file, nil
}

type RemoteFileWriter struct {
	ctx               context.Context
	fileType          FileType
	isFulltextIndexed bool
	db                *sql.DB
	dialect           string
	storage           Storage
	exists            bool
	fileID            [16]byte
	parentID          [16]byte
	filePath          string
	size              int64
	buf               *bytes.Buffer
	gzipWriter        *gzip.Writer
	modTime           time.Time
	storageWriter     *io.PipeWriter
	storageResult     chan error
	writeFailed       bool
}

func (file *RemoteFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	if file.fileType.IsObject {
		n, err = file.storageWriter.Write(p)
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			n, err = file.gzipWriter.Write(p)
		} else {
			n, err = file.buf.Write(p)
		}
	}
	file.size += int64(n)
	if err != nil {
		file.writeFailed = true
	}
	return n, err
}

func (file *RemoteFileWriter) ReadFrom(r io.Reader) (n int64, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	if file.fileType.IsObject {
		n, err = io.Copy(file.storageWriter, r)
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			n, err = io.Copy(file.gzipWriter, r)
		} else {
			n, err = file.buf.ReadFrom(r)
		}
	}
	file.size += int64(n)
	if err != nil {
		file.writeFailed = true
	}
	return n, err
}

func (file *RemoteFileWriter) Close() error {
	if file.fileType.IsObject {
		if file.storageWriter == nil {
			return fs.ErrClosed
		}
		file.storageWriter.Close()
		file.storageWriter = nil
		err := <-file.storageResult
		if err != nil {
			return err
		}
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			if file.gzipWriter == nil {
				return fs.ErrClosed
			}
			err := file.gzipWriter.Close()
			if err != nil {
				return err
			}
			defer func() {
				file.gzipWriter.Reset(io.Discard)
				gzipWriterPool.Put(file.gzipWriter)
				file.gzipWriter = nil
				if file.buf.Cap() <= maxPoolableBufferCapacity {
					file.buf.Reset()
					bufPool.Put(file.buf)
				}
				file.buf = nil
			}()
		} else {
			if file.buf == nil {
				return fs.ErrClosed
			}
			defer func() {
				if file.buf.Cap() <= maxPoolableBufferCapacity {
					file.buf.Reset()
					bufPool.Put(file.buf)
				}
				file.buf = nil
			}()
		}
	}
	if file.writeFailed {
		if file.fileType.IsObject {
			_ = file.storage.Delete(file.ctx, encodeUUID(file.fileID)+path.Ext(file.filePath))
		}
		return nil
	}

	// If file exists, just have to update the file entry in the database.
	if file.exists {
		if file.fileType.IsObject {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format:  "UPDATE files SET text = NULL, data = NULL, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
				Values: []any{
					sq.Int64Param("size", file.size),
					sq.TimeParam("modTime", file.modTime),
					sq.UUIDParam("fileID", file.fileID),
				},
			})
			if err != nil {
				return err
			}
		} else {
			if file.fileType.IsGzippable && !file.isFulltextIndexed {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = NULL, data = {data}, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("data", file.buf.Bytes()),
						sq.Int64Param("size", file.size),
						sq.TimeParam("modTime", file.modTime),
						sq.UUIDParam("fileID", file.fileID),
					},
				})
				if err != nil {
					return err
				}
			} else {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = {text}, data = NULL, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("text", file.buf.Bytes()),
						sq.Int64Param("size", file.size),
						sq.TimeParam("modTime", file.modTime),
						sq.UUIDParam("fileID", file.fileID),
					},
				})
				if err != nil {
					return err
				}
			}
		}
		return nil
	}

	// If we reach here it means file doesn't exist. Insert a new file entry
	// into the database.
	if file.fileType.IsObject {
		_, err := sq.Exec(file.ctx, file.db, sq.Query{
			Dialect: file.dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, size, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, {parentID}, {filePath}, {size}, {modTime}, {modTime}, FALSE)",
			Values: []any{
				sq.UUIDParam("fileID", file.fileID),
				sq.UUIDParam("parentID", file.parentID),
				sq.StringParam("filePath", file.filePath),
				sq.Int64Param("size", file.size),
				sq.TimeParam("modTime", file.modTime),
			},
		})
		if err != nil {
			go file.storage.Delete(context.Background(), encodeUUID(file.fileID)+path.Ext(file.filePath))
			return err
		}
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, size, data, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {size}, {data}, {modTime}, {modTime}, FALSE)",
				Values: []any{
					sq.UUIDParam("fileID", file.fileID),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.Int64Param("size", file.size),
					sq.BytesParam("data", file.buf.Bytes()),
					sq.TimeParam("modTime", file.modTime),
				},
			})
			if err != nil {
				return err
			}
		} else {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, size, text, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {size}, {text}, {modTime}, {modTime}, FALSE)",
				Values: []any{
					sq.UUIDParam("fileID", file.fileID),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.Int64Param("size", file.size),
					sq.BytesParam("text", file.buf.Bytes()),
					sq.TimeParam("modTime", file.modTime),
				},
			})
			if err != nil {
				return err
			}
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
	// TODO: return syscall.ENOTDIR if name is not a dir? Or follow stdlib and
	// return fs.ErrNotExist?
	var condition sq.Expression
	if name == "." {
		condition = sq.Expr("parent_id IS NULL")
	} else {
		condition = sq.Expr("parent_id = (SELECT file_id FROM files WHERE file_path = {})", name)
	}
	dirEntries, err := sq.FetchAll(fsys.ctx, fsys.filesDB, sq.Query{
		Dialect: fsys.filesDialect,
		Format:  "SELECT {*} FROM files WHERE {condition}",
		Values: []any{
			sq.Param("condition", condition),
		},
	}, func(row *sq.Row) fs.DirEntry {
		file := &RemoteFileInfo{}
		file.FileID = row.UUID("file_id")
		file.FilePath = row.String("file_path")
		file.isDir = row.Bool("is_dir")
		file.size = row.Int64("size")
		file.modTime = row.Time("mod_time")
		file.CreationTime = row.Time("creation_time")
		return file
	})
	if err != nil {
		return nil, err
	}
	return dirEntries, nil
}

func (fsys *RemoteFS) Mkdir(name string, _ fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil
	}
	modTime := time.Now().UTC()
	parentDir := path.Dir(name)
	if parentDir == "." {
		_, err := sq.Exec(fsys.ctx, fsys.filesDB, sq.Query{
			Dialect: fsys.filesDialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, {modTime}, TRUE)",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", name),
				sq.TimeParam("modTime", modTime),
			},
		})
		if err != nil {
			if fsys.filesErrorCode == nil {
				return err
			}
			errcode := fsys.filesErrorCode(err)
			if IsKeyViolation(fsys.filesDialect, errcode) {
				return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
			}
			return err
		}
	} else {
		_, err = sq.Exec(fsys.ctx, fsys.filesDB, sq.Query{
			Dialect: fsys.filesDialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, {modTime}, TRUE)",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("parentDir", parentDir),
				sq.StringParam("filePath", name),
				sq.TimeParam("modTime", modTime),
			},
		})
		if err != nil {
			if fsys.filesErrorCode == nil {
				return err
			}
			errcode := fsys.filesErrorCode(err)
			if IsKeyViolation(fsys.filesDialect, errcode) {
				return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
			}
			return err
		}
	}
	return nil
}

func (fsys *RemoteFS) MkdirAll(name string, _ fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdirall", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil
	}
	tx, err := fsys.filesDB.BeginTx(fsys.ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert the top level directory (no parent), ignoring duplicates.
	modTime := time.Now().UTC()
	segments := strings.Split(name, "/")
	switch fsys.filesDialect {
	case "sqlite", "postgres":
		_, err := sq.Exec(fsys.ctx, tx, sq.Query{
			Dialect: fsys.filesDialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, {modTime}, TRUE)" +
				" ON CONFLICT DO NOTHING",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", segments[0]),
				sq.TimeParam("modTime", modTime),
			},
		})
		if err != nil {
			return err
		}
	case "mysql":
		_, err := sq.Exec(fsys.ctx, tx, sq.Query{
			Dialect: fsys.filesDialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, creation_time is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, {modTime}, TRUE)" +
				" ON DUPLICATE KEY UPDATE file_id = file_id",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", segments[0]),
				sq.TimeParam("modTime", modTime),
			},
		})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported dialect %q", fsys.filesDialect)
	}

	// Insert the rest of the directories, ignoring duplicates.
	if len(segments) > 1 {
		var preparedExec *sq.PreparedExec
		switch fsys.filesDialect {
		case "sqlite", "postgres":
			preparedExec, err = sq.PrepareExec(fsys.ctx, tx, sq.Query{
				Dialect: fsys.filesDialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, {modTime}, TRUE)" +
					" ON CONFLICT DO NOTHING",
				Values: []any{
					sq.Param("fileID", nil),
					sq.Param("parentDir", nil),
					sq.Param("filePath", nil),
					sq.Param("modTime", nil),
				},
			})
			if err != nil {
				return err
			}
		case "mysql":
			preparedExec, err = sq.PrepareExec(fsys.ctx, tx, sq.Query{
				Dialect: fsys.filesDialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, {modTime}, TRUE)" +
					" ON DUPLICATE KEY UPDATE file_id = file_id",
				Values: []any{
					sq.Param("fileID", nil),
					sq.Param("parentDir", nil),
					sq.Param("filePath", nil),
					sq.Param("modTime", nil),
				},
			})
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported dialect %q", fsys.filesDialect)
		}
		defer preparedExec.Close()
		for i := 1; i < len(segments); i++ {
			parentDir := path.Join(segments[:i]...)
			filePath := path.Join(segments[:i+1]...)
			_, err := preparedExec.Exec(fsys.ctx,
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("parentDir", parentDir),
				sq.StringParam("filePath", filePath),
				sq.TimeParam("modTime", modTime),
			)
			if err != nil {
				return err
			}
		}
		err = preparedExec.Close()
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (fsys *RemoteFS) Remove(name string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") || name == "." {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}
	file, err := sq.FetchOne(fsys.ctx, fsys.filesDB, sq.Query{
		Dialect: fsys.filesDialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) (file struct {
		fileID      [16]byte
		filePath    string
		isDir       bool
		hasChildren bool
	}) {
		file.fileID = row.UUID("file_id")
		file.filePath = row.String("file_path")
		file.isDir = row.Bool("is_dir")
		file.hasChildren = row.Bool("EXISTS (SELECT 1 FROM files WHERE file_path LIKE {pattern} ESCAPE '\\')", sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(name)+"/%"))
		return file
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
		}
		return err
	}
	if file.hasChildren {
		return &fs.PathError{Op: "remove", Path: name, Err: syscall.ENOTEMPTY}
	}
	switch path.Ext(name) {
	case ".jpeg", ".jpg", ".png", ".webp", ".gif":
		err = fsys.storage.Delete(fsys.ctx, encodeUUID(file.fileID)+path.Ext(file.filePath))
		if err != nil {
			return err
		}
	}
	_, err = sq.Exec(fsys.ctx, fsys.filesDB, sq.Query{
		Dialect: fsys.filesDialect,
		Format:  "DELETE FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (fsys *RemoteFS) RemoveAll(name string) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") || name == "." {
		return &fs.PathError{Op: "removeall", Path: name, Err: fs.ErrInvalid}
	}
	pattern := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(name) + "/%"
	cursor, err := sq.FetchCursor(fsys.ctx, fsys.filesDB, sq.Query{
		Dialect: fsys.filesDialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE (file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\')" +
			" AND NOT is_dir" +
			" AND (" +
			"file_path LIKE '%.jpeg'" +
			" OR file_path LIKE '%.jpg'" +
			" OR file_path LIKE '%.png'" +
			" OR file_path LIKE '%.webp'" +
			" OR file_path LIKE '%.gif'" +
			")",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	}, func(row *sq.Row) (file struct {
		fileID   [16]byte
		filePath string
	}) {
		file.fileID = row.UUID("file_id")
		file.filePath = row.String("file_path")
		return file
	})
	if err != nil {
		return err
	}
	defer cursor.Close()
	var waitGroup sync.WaitGroup
	for cursor.Next() {
		file, err := cursor.Result()
		if err != nil {
			return err
		}
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			err := fsys.storage.Delete(fsys.ctx, encodeUUID(file.fileID)+path.Ext(file.filePath))
			if err != nil {
				fsys.logger.Error(err.Error())
			}
		}()
	}
	err = cursor.Close()
	if err != nil {
		return err
	}
	waitGroup.Wait()
	_, err = sq.Exec(fsys.ctx, fsys.filesDB, sq.Query{
		Dialect: fsys.filesDialect,
		Format:  "DELETE FROM files WHERE file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\'",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (fsys *RemoteFS) Rename(oldname, newname string) error {
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
	tx, err := fsys.filesDB.BeginTx(fsys.ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var deletedFileID [16]byte
	switch fsys.filesDialect {
	case "sqlite", "postgres":
		deletedFileID, err = sq.FetchOne(fsys.ctx, tx, sq.Query{
			Dialect: fsys.filesDialect,
			Format:  "DELETE FROM files WHERE file_path = {newname} AND NOT is_dir RETURNING {*}",
			Values: []any{
				sq.StringParam("newname", newname),
			},
		}, func(row *sq.Row) (fileID [16]byte) {
			return row.UUID("file_id")
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// If the parent changes, also update the parent_id.
		var updateParent sq.Expression
		if path.Dir(oldname) != path.Dir(newname) {
			updateParent = sq.Expr(", parent_id = (SELECT file_id FROM files WHERE file_path = {})", path.Dir(newname))
		}
		oldnameIsDir, err := sq.FetchOne(fsys.ctx, tx, sq.Query{
			Dialect: fsys.filesDialect,
			Format:  "UPDATE files SET file_path = {newname}, mod_time = {modTime}{updateParent} WHERE file_path = {oldname} RETURNING {*}",
			Values: []any{
				sq.StringParam("newname", newname),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.Param("updateParent", updateParent),
				sq.StringParam("oldname", oldname),
			},
		}, func(row *sq.Row) bool {
			return row.Bool("is_dir")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return &fs.PathError{Op: "rename", Path: oldname, Err: fs.ErrNotExist}
			}
			if fsys.filesErrorCode != nil {
				errcode := fsys.filesErrorCode(err)
				if IsKeyViolation(fsys.filesDialect, errcode) {
					// We weren't able to delete {newname} earlier, which means it is a
					// directory.
					return &fs.PathError{Op: "rename", Path: newname, Err: syscall.EISDIR}
				}
			}
			return err
		}
		if oldnameIsDir {
			_, err := sq.Exec(fsys.ctx, tx, sq.Query{
				Dialect: fsys.filesDialect,
				Format:  "UPDATE files SET file_path = {filePath}, mod_time = {modTime} WHERE file_path LIKE {pattern} ESCAPE '\\'",
				Values: []any{
					sq.Param("filePath", sq.Expr("concat({}, substring(file_path, {}))", newname, utf8.RuneCountInString(oldname)+1)),
					sq.TimeParam("modTime", time.Now().UTC()),
					sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(oldname)+"/%"),
				},
			})
			if err != nil {
				return err
			}
		} else {
			if path.Ext(oldname) != path.Ext(newname) {
				return fmt.Errorf("file extension cannot be changed")
			}
		}
	case "mysql":
		result, err := sq.FetchOne(fsys.ctx, tx, sq.Query{
			Dialect: fsys.filesDialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {newname}",
			Values: []any{
				sq.StringParam("newname", newname),
			},
		}, func(row *sq.Row) (result struct {
			FileID [16]byte
			IsDir  bool
		}) {
			result.FileID = row.UUID("file_id")
			result.IsDir = row.Bool("is_dir")
			return result
		})
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		} else {
			if result.IsDir {
				return &fs.PathError{Op: "rename", Path: newname, Err: syscall.EISDIR}
			}
			_, err := sq.Exec(fsys.ctx, tx, sq.Query{
				Dialect: fsys.filesDialect,
				Format:  "DELETE FROM files WHERE file_path = {newname}",
				Values: []any{
					sq.StringParam("newname", newname),
				},
			})
			if err != nil {
				return err
			}
			deletedFileID = result.FileID
		}
		oldnameIsDir, err := sq.FetchOne(fsys.ctx, tx, sq.Query{
			Dialect: fsys.filesDialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {oldname}",
			Values: []any{
				sq.StringParam("oldname", oldname),
			},
		}, func(row *sq.Row) bool {
			return row.Bool("is_dir")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return &fs.PathError{Op: "rename", Path: oldname, Err: fs.ErrNotExist}
			}
			return err
		}
		if !oldnameIsDir && path.Ext(oldname) != path.Ext(newname) {
			return fmt.Errorf("file extension cannot be changed")
		}
		// If the parent changes, also update the parent_id.
		var updateParent sq.Expression
		if path.Dir(oldname) != path.Dir(newname) {
			updateParent = sq.Expr(", parent_id = (SELECT file_id FROM files WHERE file_path = {})", path.Dir(newname))
		}
		_, err = sq.Exec(fsys.ctx, tx, sq.Query{
			Dialect: fsys.filesDialect,
			Format:  "UPDATE files SET file_path = {newname}, mod_time = {modTime}{updateParent} WHERE file_path = {oldname}",
			Values: []any{
				sq.StringParam("newname", newname),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.Param("updateParent", updateParent),
				sq.StringParam("oldname", oldname),
			},
		})
		if err != nil {
			return err
		}
		_, err = sq.Exec(fsys.ctx, tx, sq.Query{
			Dialect: fsys.filesDialect,
			Format:  "UPDATE files SET file_path = {filePath}, mod_time = {modTime} WHERE file_path LIKE {pattern} ESCAPE '\\'",
			Values: []any{
				sq.Param("filePath", sq.Expr("concat({}, substring(file_path, {}))", newname, utf8.RuneCountInString(oldname)+1)),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(oldname)+"/%"),
			},
		})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported dialect %q", fsys.filesDialect)
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	if deletedFileID != [16]byte{} {
		err := fsys.storage.Delete(fsys.ctx, encodeUUID(deletedFileID)+path.Ext(newname))
		if err != nil {
			return err
		}
	}
	return nil
}

type Storage interface {
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Put(ctx context.Context, key string, reader io.Reader) error
	Delete(ctx context.Context, key string) error
	Copy(ctx context.Context, srcKey, destKey string) error
}

type S3Storage struct {
	Client *s3.Client
	Bucket string
}

var _ Storage = (*S3Storage)(nil)

type S3StorageConfig struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
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
				return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
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

func (storage *S3Storage) Copy(ctx context.Context, srcKey, destKey string) error {
	_, err := storage.Client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     &storage.Bucket,
		CopySource: aws.String(srcKey),
		Key:        aws.String(destKey),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "NoSuchKey" {
				return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrNotExist}
			}
		}
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
		return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
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

func (storage *InMemoryStorage) Copy(ctx context.Context, srcKey, destKey string) error {
	storage.mu.Lock()
	value, ok := storage.entries[srcKey]
	if !ok {
		return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrNotExist}
	}
	storage.entries[destKey] = value
	storage.mu.Unlock()
	return nil
}

type LocalStorage struct {
	rootDir string
	tempDir string
}

func NewLocalStorage(rootDir, tempDir string) *LocalStorage {
	return &LocalStorage{
		rootDir: filepath.FromSlash(rootDir),
		tempDir: filepath.FromSlash(tempDir),
	}
}

func (storage *LocalStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
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
			return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	return file, nil
}

func (storage *LocalStorage) Put(ctx context.Context, key string, reader io.Reader) error {
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
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			err = os.Mkdir(filepath.Join(storage.rootDir, key[:4]), 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			file, err = os.OpenFile(filepath.Join(storage.rootDir, key[:4], key), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
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

func (storage *LocalStorage) Delete(ctx context.Context, key string) error {
	err := ctx.Err()
	if err != nil {
		return err
	}
	if len(key) < 4 {
		return &fs.PathError{Op: "delete", Path: key, Err: fs.ErrInvalid}
	}
	err = os.Remove(filepath.Join(storage.rootDir, key[:4], key))
	if err != nil {
		return err
	}
	return nil
}

func (storage *LocalStorage) Copy(ctx context.Context, srcKey, destKey string) error {
	err := ctx.Err()
	if err != nil {
		return err
	}
	if len(srcKey) < 4 {
		return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrInvalid}
	}
	if len(destKey) < 4 {
		return &fs.PathError{Op: "copy", Path: destKey, Err: fs.ErrInvalid}
	}
	srcFile, err := os.Open(filepath.Join(storage.rootDir, srcKey[:4], srcKey))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrNotExist}
		}
		return err
	}
	defer srcFile.Close()
	destFile, err := os.OpenFile(filepath.Join(storage.rootDir, destKey[:4], destKey), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer destFile.Close()
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return err
	}
	err = destFile.Close()
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

func isFulltextIndexed(filePath string) bool {
	ext := path.Ext(filePath)
	head, tail, _ := strings.Cut(filePath, "/")
	if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
		head, tail, _ = strings.Cut(tail, "/")
	}
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
