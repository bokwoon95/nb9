package nb9

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/nb9/sq"
	"golang.org/x/crypto/blake2b"
)

type fileEntry struct {
	Name    string    `json:"name,omitempty"`
	Size    int64     `json:"size,omitempty"`
	ModTime time.Time `json:"modTime,omitempty"`
	IsDir   bool      `json:"isDir,omitempty"`
}

type fileResponse struct {
	Status      Status         `json:"status"`
	ContentSite string         `json:"contentSite,omitempty"`
	Username    sql.NullString `json:"username,omitempty"`
	SitePrefix  string         `json:"sitePrefix,omitempty"`
	Path        string         `json:"path"`
	IsDir       bool           `json:"isDir,omitempty"`
	ModTime     time.Time      `json:"modTime,omitempty"`

	Files []fileEntry `json:"fileEntries,omitempty"`
	Sites []string    `json:"sites,omitempty"`
	Users []string    `json:"users,omitempty"`

	Content        string      `json:"content,omitempty"`
	URL            string      `json:"url,omitempty"`
	BelongsTo      string      `json:"belongsTo,omitempty"`
	AssetDir       string      `json:"assetDir,omitempty"`
	Assets         []fileEntry `json:"assets,omitempty"`
	TemplateErrors []string    `json:"templateErrors,omitempty"`
}

func (nbrew *Notebrew) fileHandler(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string) {
	file, err := nbrew.FS.Open(path.Join(".", sitePrefix, filePath))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			notFound(w, r)
			return
		}
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	if fileInfo.IsDir() {
		nbrew.listDirectory(w, r, username, sitePrefix, filePath)
		return
	}
	fileType, ok := fileTypes[path.Ext(filePath)]
	if !ok {
		notFound(w, r)
		return
	}

	var isEditable bool
	n := strings.Index(filePath, "/")
	if n < 0 {
		notFound(w, r)
		return
	}
	head, tail := filePath[:n], filePath[n+1:]
	switch head {
	case "notes":
		isEditable = fileType.Ext == ".html" || fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md" || fileType.Ext == ".txt"
	case "pages":
		isEditable = fileType.Ext == ".html"
		if !isEditable {
			notFound(w, r)
			return
		}
	case "posts":
		isEditable = fileType.Ext == ".md"
		if !isEditable {
			notFound(w, r)
			return
		}
	case "output":
		n := strings.Index(tail, "/")
		if n < 0 {
			notFound(w, r)
			return
		}
		switch tail[:n] {
		case "posts":
			isEditable = false
		case "themes":
			isEditable = fileType.Ext == ".html" || fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md" || fileType.Ext == ".txt"
		default:
			isEditable = fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md"
		}
	default:
		notFound(w, r)
		return
	}

	switch r.Method {
	case "GET":
		var response fileResponse
		_, err = nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentSite = nbrew.contentSite(sitePrefix)
		response.Username = sql.NullString{String: username, Valid: nbrew.UsersDB != nil}
		response.SitePrefix = sitePrefix
		response.Path = filePath
		response.IsDir = fileInfo.IsDir()
		response.ModTime = fileInfo.ModTime()
		if response.Status == "" {
			response.Status = GetSuccess
		}

		if isEditable {
			if remoteFile, ok := file.(*RemoteFile); ok {
				response.Content = remoteFile.buf.String()
			} else {
				var b strings.Builder
				b.Grow(int(fileInfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				response.Content = b.String()
			}
		}

		switch head {
		case "pages":
			if tail == "index.html" {
				response.AssetDir = "output"
				response.URL = response.ContentSite
			} else {
				response.AssetDir = path.Join("output", strings.TrimSuffix(tail, ".html"))
				response.URL = response.ContentSite + "/" + strings.TrimSuffix(tail, ".html") + "/"
			}
			if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
				response.Assets, err = sq.FetchAll(r.Context(), remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {assetDir})" +
						" AND NOT is_dir" +
						" AND (" +
						"file_path LIKE '%.jpeg'" +
						" OR file_path LIKE '%.jpg'" +
						" OR file_path LIKE '%.png'" +
						" OR file_path LIKE '%.webp'" +
						" OR file_path LIKE '%.gif'" +
						" OR file_path LIKE '%.css'" +
						" OR file_path LIKE '%.js'" +
						" OR file_path LIKE '%.md'" +
						") " +
						" ORDER BY file_path",
					Values: []any{
						sq.StringParam("assetDir", path.Join(sitePrefix, response.AssetDir)),
					},
				}, func(row *sq.Row) fileEntry {
					return fileEntry{
						Name: path.Base(row.String("file_path")),
						Size: row.Int64("{}", sq.DialectExpression{
							Default: sq.Expr("COALESCE(OCTET_LENGTH(text), OCTET_LENGTH(data), size, 0)"),
							Cases: []sq.DialectCase{{
								Dialect: "sqlite",
								Result:  sq.Expr("COALESCE(LENGTH(CAST(text AS BLOB)), LENGTH(CAST(data AS BLOB)), size, 0)"),
							}},
						}),
						ModTime: row.Time("mod_time"),
					}
				})
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			} else {
				dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, response.AssetDir))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				for _, dirEntry := range dirEntries {
					if dirEntry.IsDir() {
						continue
					}
					name := dirEntry.Name()
					switch path.Ext(name) {
					case ".jpeg", ".jpg", ".png", ".webp", "gif", ".css", ".js", ".md":
						fileInfo, err := dirEntry.Info()
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
							internalServerError(w, r, err)
							return
						}
						response.Assets = append(response.Assets, fileEntry{
							Name:    name,
							Size:    fileInfo.Size(),
							ModTime: fileInfo.ModTime(),
						})
					}
				}
			}
		case "posts":
			response.AssetDir = path.Join("output", strings.TrimSuffix(filePath, ".md"))
			response.URL = response.ContentSite + "/" + strings.TrimSuffix(filePath, ".md") + "/"
			if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
				response.Assets, err = sq.FetchAll(r.Context(), remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {assetDir})" +
						" AND NOT is_dir" +
						" AND (" +
						"file_path LIKE '%.jpeg'" +
						" OR file_path LIKE '%.jpg'" +
						" OR file_path LIKE '%.png'" +
						" OR file_path LIKE '%.webp'" +
						" OR file_path LIKE '%.gif'" +
						") " +
						" ORDER BY file_path",
					Values: []any{
						sq.StringParam("assetDir", path.Join(sitePrefix, response.AssetDir)),
					},
				}, func(row *sq.Row) fileEntry {
					return fileEntry{
						Name: path.Base(row.String("file_path")),
						Size: row.Int64("{}", sq.DialectExpression{
							Default: sq.Expr("COALESCE(OCTET_LENGTH(text), OCTET_LENGTH(data), size, 0)"),
							Cases: []sq.DialectCase{{
								Dialect: "sqlite",
								Result:  sq.Expr("COALESCE(LENGTH(CAST(text AS BLOB)), LENGTH(CAST(data AS BLOB)), size, 0)"),
							}},
						}),
						ModTime: row.Time("mod_time"),
					}
				})
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			} else {
				dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, response.AssetDir))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				for _, dirEntry := range dirEntries {
					if dirEntry.IsDir() {
						continue
					}
					name := dirEntry.Name()
					switch path.Ext(name) {
					case ".jpeg", ".jpg", ".png", ".webp", "gif":
						fileInfo, err := dirEntry.Info()
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
							internalServerError(w, r, err)
							return
						}
						response.Assets = append(response.Assets, fileEntry{
							Name:    name,
							Size:    fileInfo.Size(),
							ModTime: fileInfo.ModTime(),
						})
					}
				}
			}
		case "output":
			n := strings.Index(tail, "/")
			if tail[:n] != "posts" && tail[:n] != "themes" && isEditable {
				response.BelongsTo = path.Join("pages", path.Dir(tail)+".html")
			}
		}

		if r.Form.Has("api") {
			w.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(w)
			encoder.SetEscapeHTML(false)
			err := encoder.Encode(&response)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
			}
			return
		}

		if isEditable {
			referer := getReferer(r)
			funcMap := map[string]any{
				"join":             path.Join,
				"dir":              path.Dir,
				"base":             path.Base,
				"ext":              path.Ext,
				"hasPrefix":        strings.HasPrefix,
				"hasSuffix":        strings.HasSuffix,
				"trimPrefix":       strings.TrimPrefix,
				"fileSizeToString": fileSizeToString,
				"stylesCSS":        func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS":       func() template.JS { return template.JS(baselineJS) },
				"referer":          func() string { return referer },
				"safeHTML":         func(s string) template.HTML { return template.HTML(s) },
				"head": func(s string) string {
					head, _, _ := strings.Cut(s, "/")
					return head
				},
				"tail": func(s string) string {
					_, tail, _ := strings.Cut(s, "/")
					return tail
				},
			}
			tmpl, err := template.New("file_handler.html").Funcs(funcMap).ParseFS(rootFS, "embed/file_handler.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
			executeTemplate(w, r, response.ModTime, tmpl, &response)
			return
		}

		// If we reach here, it means the file is not editable and we serve the
		// file content directly.
		hasher := hashPool.Get().(hash.Hash)
		hasher.Reset()
		defer hashPool.Put(hasher)
		if !fileType.IsGzippable {
			if file, ok := file.(io.ReadSeeker); ok {
				_, err := io.Copy(hasher, file)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				_, err = file.Seek(0, io.SeekStart)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				var b [blake2b.Size256]byte
				if _, ok := w.Header()["Content-Type"]; !ok {
					w.Header().Set("Content-Type", fileType.ContentType)
				}
				w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
				http.ServeContent(w, r, "", fileInfo.ModTime(), file)
				return
			}
		}
		// Stream file if too big to buffer in memory.
		if fileInfo.Size() > 5<<20 /* 5MB */ {
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Add("Cache-Control", "max-age: 300, stale-while-revalidate" /* 5 minutes */)
			_, err := io.Copy(w, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				return
			}
			return
		}
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		multiWriter := io.MultiWriter(hasher, buf)
		if fileType.IsGzippable {
			gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
			gzipWriter.Reset(multiWriter)
			defer gzipWriterPool.Put(gzipWriter)
			_, err = io.Copy(gzipWriter, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			err = gzipWriter.Close()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		} else {
			_, err = io.Copy(multiWriter, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		var b [blake2b.Size256]byte
		if _, ok := w.Header()["Content-Type"]; !ok {
			if fileType.Ext == ".html" {
				// Serve HTML as plain text so the user can see the source.
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			} else {
				w.Header().Set("Content-Type", fileType.ContentType)
			}
		}
		if fileType.IsGzippable {
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
		http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
	case "POST":
		if !isEditable {
			methodNotAllowed(w, r)
			return
		}
	default:
		methodNotAllowed(w, r)
	}
}

func (nbrew *Notebrew) listDirectory(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string) {
	if r.Method != "GET" {
		methodNotAllowed(w, r)
		return
	}
}

// displayFile
// updateFile
// listDir
