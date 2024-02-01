package nb9

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
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
	"golang.org/x/sync/errgroup"
)

type RemoteFSConfig struct {
	FilesDB        *sql.DB
	FilesDialect   string
	FilesErrorCode func(error) string
	Storage        Storage
	UsersDB        *sql.DB
	UsersDialect   string
}

type RemoteFS struct {
	ctx            context.Context
	filesDB        *sql.DB
	filesDialect   string
	filesErrorCode func(error) string
	storage        Storage
	usersDB        *sql.DB
	usersDialect   string
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
			info:    &remoteFileInfo{filePath: ".", isDir: true},
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
			info:     &remoteFileInfo{},
		}
		row.UUID(&file.info.fileID, "file_id")
		file.info.filePath = row.String("file_path")
		file.info.isDir = row.Bool("is_dir")
		file.info.size = row.Int64("size")
		file.info.modTime = row.Time("mod_time")
		file.info.creationTime = row.Time("creation_time")
		if fileType.IsGzippable {
			b := bufPool.Get().(*bytes.Buffer).Bytes()
			row.Scan(&b, "COALESCE(text, data)")
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
	file.isFulltextIndexed = isFulltextIndexed(file.info.filePath)
	if fileType.IsGzippable && !file.isFulltextIndexed {
		// Do NOT pass file.buf directly to gzip.Reader or it will read from
		// the buffer! We want to keep file.buf unread in case someone wants to
		// reach directly into it and pulled out the raw gzipped bytes.
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
		return &remoteFileInfo{filePath: ".", isDir: true}, nil
	}
	fileInfo, err := sq.FetchOne(fsys.ctx, fsys.filesDB, sq.Query{
		Dialect: fsys.filesDialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) *remoteFileInfo {
		fileInfo := &remoteFileInfo{}
		fileInfo.filePath = row.String("file_path")
		fileInfo.isDir = row.Bool("is_dir")
		fileInfo.size = row.Int64("size")
		fileInfo.modTime = row.Time("mod_time")
		fileInfo.creationTime = row.Time("creation_time")
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

type remoteFileInfo struct {
	fileID       [16]byte
	filePath     string
	isDir        bool
	size         int64
	modTime      time.Time
	creationTime time.Time
}

func (fileInfo *remoteFileInfo) Name() string { return path.Base(fileInfo.filePath) }

func (fileInfo *remoteFileInfo) Size() int64 { return fileInfo.size }

func (fileInfo *remoteFileInfo) ModTime() time.Time { return fileInfo.modTime }

func (fileInfo *remoteFileInfo) IsDir() bool { return fileInfo.isDir }

func (fileInfo *remoteFileInfo) Sys() any { return nil }

func (fileInfo *remoteFileInfo) Type() fs.FileMode { return fileInfo.Mode().Type() }

func (fileInfo *remoteFileInfo) Info() (fs.FileInfo, error) { return fileInfo, nil }

func (fileInfo *remoteFileInfo) Mode() fs.FileMode {
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
	info              *remoteFileInfo
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
		return 0, &fs.PathError{Op: "read", Path: file.info.filePath, Err: syscall.EISDIR}
	}
	if file.fileType.IsGzippable {
		if file.isFulltextIndexed {
			return file.buf.Read(p)
		} else {
			return file.gzipReader.Read(p)
		}
	} else {
		if file.readCloser == nil {
			file.readCloser, err = file.storage.Get(file.ctx, hex.EncodeToString(file.info.fileID[:])+path.Ext(file.info.filePath))
			if err != nil {
				return 0, err
			}
		}
		return file.readCloser.Read(p)
	}
}

type emptyReader struct{}

var empty = (*emptyReader)(nil)

func (empty *emptyReader) Read(p []byte) (n int, err error) { return 0, io.EOF }

func (file *RemoteFile) Close() error {
	if file.info.isDir {
		return nil
	}
	if file.fileType.IsGzippable {
		if file.isFulltextIndexed {
			if file.buf == nil {
				return fs.ErrClosed
			}
			if file.buf.Cap() <= maxPoolableBufferCapacity {
				file.buf.Reset()
				bufPool.Put(file.buf)
			}
			file.buf = nil
		} else {
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
		}
	} else {
		if file.readCloser == nil {
			return fs.ErrClosed
		}
		err := file.readCloser.Close()
		if err != nil {
			return err
		}
		file.readCloser = nil
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
		modTime:           time.Now().UTC().Truncate(time.Second),
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
			row.UUID(&result.fileID, "file_id")
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
	}
	if fileType.IsGzippable {
		if file.isFulltextIndexed {
			file.buf = bufPool.Get().(*bytes.Buffer)
		} else {
			file.buf = bufPool.Get().(*bytes.Buffer)
			file.gzipWriter = gzipWriterPool.Get().(*gzip.Writer)
			file.gzipWriter.Reset(file.buf)
		}
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

type RemoteFileWriter struct {
	ctx               context.Context
	fileType          FileType
	isFulltextIndexed bool
	db                *sql.DB
	dialect           string
	storage           Storage
	fileID            [16]byte
	parentID          any // either nil or [16]byte
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
	if file.fileType.IsGzippable {
		if file.isFulltextIndexed {
			n, err = file.buf.Write(p)
		} else {
			n, err = file.gzipWriter.Write(p)
		}
	} else {
		n, err = file.storageWriter.Write(p)
	}
	file.size += int64(n)
	if err != nil {
		file.writeFailed = true
	}
	return n, err
}

func (file *RemoteFileWriter) Close() error {
	if file.fileType.IsGzippable {
		if file.isFulltextIndexed {
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
		} else {
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
		}
	} else {
		if file.storageWriter == nil {
			return fs.ErrClosed
		}
		file.storageWriter.Close()
		err := <-file.storageResult
		file.storageWriter = nil
		if err != nil {
			return err
		}
	}
	if file.writeFailed {
		return nil
	}

	// If file exists, just have to update the file entry in the database.
	if file.fileID != [16]byte{} {
		if file.fileType.IsGzippable {
			if file.isFulltextIndexed {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = {text}, data = NULL, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("text", file.buf.Bytes()),
						sq.Int64Param("size", file.size),
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
					Format:  "UPDATE files SET text = NULL, data = {data}, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("data", file.buf.Bytes()),
						sq.Int64Param("size", file.size),
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
					sq.Int64Param("size", file.size),
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
	if file.fileType.IsGzippable {
		if file.isFulltextIndexed {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, size, text, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {size}, {text}, {modTime}, {modTime}, FALSE)",
				Values: []any{
					sq.UUIDParam("fileID", NewID()),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.Int64Param("size", file.size),
					sq.BytesParam("text", file.buf.Bytes()),
					sq.Param("modTime", sq.Timestamp{Time: file.modTime, Valid: true}),
				},
			})
			if err != nil {
				return err
			}
		} else {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, size, data, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {size}, {data}, {modTime}, {modTime}, FALSE)",
				Values: []any{
					sq.UUIDParam("fileID", NewID()),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.Int64Param("size", file.size),
					sq.BytesParam("data", file.buf.Bytes()),
					sq.Param("modTime", sq.Timestamp{Time: file.modTime, Valid: true}),
				},
			})
			if err != nil {
				return err
			}
		}
	} else {
		_, err := sq.Exec(file.ctx, file.db, sq.Query{
			Dialect: file.dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, size, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, {parentID}, {filePath}, {size}, {modTime}, {modTime}, FALSE)",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.UUIDParam("parentID", file.parentID),
				sq.StringParam("filePath", file.filePath),
				sq.Int64Param("size", file.size),
				sq.Param("modTime", sq.Timestamp{Time: file.modTime, Valid: true}),
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
		file := &remoteFileInfo{}
		row.UUID(&file.fileID, "file_id")
		file.filePath = row.String("file_path")
		file.isDir = row.Bool("is_dir")
		file.size = row.Int64("size")
		file.modTime = row.Time("mod_time")
		file.creationTime = row.Time("creation_time")
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
	modTime := time.Now().UTC().Truncate(time.Second)
	parentDir := path.Dir(name)
	if parentDir == "." {
		_, err := sq.Exec(fsys.ctx, fsys.filesDB, sq.Query{
			Dialect: fsys.filesDialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, TRUE)",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", name),
				sq.Param("modTime", sq.Timestamp{Time: modTime, Valid: true}),
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
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, is_dir)" +
				" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, TRUE)",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("parentDir", parentDir),
				sq.StringParam("filePath", name),
				sq.Param("modTime", sq.Timestamp{Time: modTime, Valid: true}),
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
	conn, err := fsys.filesDB.Conn(fsys.ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Insert the top level directory (no parent), ignoring duplicates.
	modTime := time.Now().UTC().Truncate(time.Second)
	segments := strings.Split(name, "/")
	switch fsys.filesDialect {
	case "sqlite", "postgres":
		_, err := sq.Exec(fsys.ctx, conn, sq.Query{
			Dialect: fsys.filesDialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, TRUE)" +
				" ON CONFLICT DO NOTHING",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", segments[0]),
				sq.Param("modTime", sq.Timestamp{Time: modTime, Valid: true}),
			},
		})
		if err != nil {
			return err
		}
	case "mysql":
		_, err := sq.Exec(fsys.ctx, conn, sq.Query{
			Dialect: fsys.filesDialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, TRUE)" +
				" ON DUPLICATE KEY UPDATE file_id = file_id",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", segments[0]),
				sq.Param("modTime", sq.Timestamp{Time: modTime, Valid: true}),
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
			preparedExec, err = sq.PrepareExec(fsys.ctx, conn, sq.Query{
				Dialect: fsys.filesDialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, is_dir)" +
					" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, TRUE)" +
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
			preparedExec, err = sq.PrepareExec(fsys.ctx, conn, sq.Query{
				Dialect: fsys.filesDialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, is_dir)" +
					" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, TRUE)" +
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
				sq.Param("modTime", sq.Timestamp{Time: modTime, Valid: true}),
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
		row.UUID(&file.fileID, "file_id")
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
	case ".jpeg", ".jpg", ".png", ".webp", ".gif", ".woff", ".woff2":
		err = fsys.storage.Delete(fsys.ctx, hex.EncodeToString(file.fileID[:])+path.Ext(file.filePath))
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
	files, err := sq.FetchAll(fsys.ctx, fsys.filesDB, sq.Query{
		Dialect: fsys.filesDialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE (file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\')" +
			" AND file_path LIKE '%.jpeg'" +
			" AND file_path LIKE '%.jpg'" +
			" AND file_path LIKE '%.png'" +
			" AND file_path LIKE '%.webp'" +
			" AND file_path LIKE '%.gif'" +
			" AND file_path LIKE '%.woff'" +
			" AND file_path LIKE '%.woff2'",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	}, func(row *sq.Row) (file struct {
		fileID   [16]byte
		filePath string
	}) {
		row.UUID(&file.fileID, "file_id")
		file.filePath = row.String("file_path")
		return file
	})
	g, ctx := errgroup.WithContext(fsys.ctx)
	for _, file := range files {
		file := file
		g.Go(func() error {
			return fsys.storage.Delete(ctx, hex.EncodeToString(file.fileID[:])+path.Ext(file.filePath))
		})
	}
	err = g.Wait()
	if err != nil {
		return err
	}
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
		return fmt.Errorf("file extension cannot be renamed")
	}
	_, err = sq.Exec(fsys.ctx, tx, sq.Query{
		Dialect: fsys.filesDialect,
		Format:  "DELETE FROM files WHERE file_path = {newname} AND NOT is_dir",
		Values: []any{
			sq.StringParam("newname", newname),
		},
	})
	if err != nil {
		return err
	}
	_, err = sq.Exec(fsys.ctx, tx, sq.Query{
		Dialect: fsys.filesDialect,
		Format:  "UPDATE files SET file_path = {newname}, mod_time = {modTime} WHERE file_path = {oldname}",
		Values: []any{
			sq.StringParam("newname", newname),
			sq.Param("modTime", sq.Timestamp{Time: time.Now().UTC(), Valid: true}),
			sq.StringParam("oldname", oldname),
		},
	})
	if err != nil {
		if fsys.filesErrorCode == nil {
			return err
		}
		errcode := fsys.filesErrorCode(err)
		if IsKeyViolation(fsys.filesDialect, errcode) {
			// We weren't able to delete {newname} earlier, which means it is a
			// directory.
			return &fs.PathError{Op: "rename", Path: newname, Err: syscall.EISDIR}
		}
		return err
	}
	if oldnameIsDir {
		_, err = sq.Exec(fsys.ctx, tx, sq.Query{
			Dialect: fsys.filesDialect,
			Format:  "UPDATE files SET file_path = {filePath}, mod_time = {modTime} WHERE file_path LIKE {pattern} ESCAPE '\\'",
			Values: []any{
				sq.Param("filePath", sq.DialectExpression{
					Default: sq.Expr("{} || SUBSTR(file_path, {})", newname, len(oldname)+1),
					Cases: []sq.DialectCase{{
						Dialect: "mysql",
						Result:  sq.Expr("CONCAT({}, SUBSTR(file_path, {}))", newname, len(oldname)+1),
					}},
				}),
				sq.Param("modTime", sq.Timestamp{Time: time.Now().UTC(), Valid: true}),
				sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(oldname)+"/%"),
			},
		})
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
			return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
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

func (storage *FileStorage) Delete(ctx context.Context, key string) error {
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
