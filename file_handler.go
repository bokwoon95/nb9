package nb9

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bokwoon95/nb9/sq"
	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"
	"golang.org/x/sync/errgroup"
)

type fileEntry struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size,omitempty"`
	ModTime time.Time `json:"modTime,omitempty"`
	IsDir   bool      `json:"isDir,omitempty"`
}

type siteEntry struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

type fileResponse struct {
	Status      string         `json:"status"`
	ContentSite string         `json:"contentSite,omitempty"`
	Username    sql.NullString `json:"username,omitempty"`
	SitePrefix  string         `json:"sitePrefix,omitempty"`
	Path        string         `json:"path"`
	IsDir       bool           `json:"isDir,omitempty"`
	ModTime     time.Time      `json:"modTime,omitempty"`

	Files           []fileEntry `json:"fileEntries,omitempty"`
	HasPreviousFile bool        `json:"hasPreviousFile,omitempty"`
	NextFile        string      `json:"nextFile,omitempty"`
	Sites           []siteEntry `json:"sites,omitempty"`
	HasPreviousSite bool        `json:"hasPreviousSite,omitempty"`
	NextSite        string      `json:"nextSite,omitempty"`
	Limit           int         `json:"limit,omitempty"`

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
		if r.Method != "GET" {
			methodNotAllowed(w, r)
			return
		}
		if filePath == "" {
			nbrew.listRootDirectory(w, r, username, sitePrefix, filePath, fileInfo.ModTime())
			return
		}
		nbrew.listDirectory(w, r, username, sitePrefix, filePath, fileInfo.ModTime())
		return
	}
	fileType, ok := fileTypes[path.Ext(filePath)]
	if !ok {
		notFound(w, r)
		return
	}

	// Figure out if the file is a user-editable file.
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
			response.Status = "GetSuccess"
		}

		if isEditable {
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

		switch head {
		case "pages":
			if tail == "index.html" {
				response.URL = response.ContentSite
				response.AssetDir = "output"
			} else {
				response.URL = response.ContentSite + "/" + strings.TrimSuffix(tail, ".html") + "/"
				response.AssetDir = path.Join("output", strings.TrimSuffix(tail, ".html"))
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
						Name:    path.Base(row.String("file_path")),
						Size:    row.Int64("size"),
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
			response.URL = response.ContentSite + "/" + strings.TrimSuffix(filePath, ".md") + "/"
			response.AssetDir = path.Join("output", strings.TrimSuffix(filePath, ".md"))
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
						Name:    path.Base(row.String("file_path")),
						Size:    row.Int64("size"),
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

		if !isEditable {
			var cacheControl string
			switch fileType.Ext {
			case ".html":
				cacheControl = "no-cache, must-revalidate"
				fileType.ContentType = "text/plain; charset=utf-8"
			case ".eot", ".otf", ".ttf", ".woff", ".woff2":
				cacheControl = "no-cache, stale-while-revalidate, max-age=2592000" /* 30 days */
			default:
				cacheControl = "no-cache, stale-while-revalidate, max-age=120" /* 2 minutes */
			}
			serveFile(w, r, file, fileInfo, fileType, cacheControl)
			return
		}

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
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response fileResponse) {
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
			err := nbrew.setSession(w, r, "flash", &response)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, filePath), http.StatusFound)
		}

		if !isEditable {
			methodNotAllowed(w, r)
			return
		}

		var request struct {
			Content string `json:"content"`
		}
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&request)
			if err != nil {
				badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			request.Content = r.FormValue("content")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := fileResponse{
			ContentSite: nbrew.contentSite(sitePrefix),
			Username:    sql.NullString{String: username, Valid: nbrew.UsersDB != nil},
			SitePrefix:  sitePrefix,
			Path:        filePath,
			IsDir:       fileInfo.IsDir(),
			ModTime:     fileInfo.ModTime(),
			Content:     request.Content,
		}

		if nbrew.UsersDB != nil {
			// TODO: check if the owner has exceeded his storage limit, then
			// defer a function that will calculate and update the new storage
			// used after the file has been saved.
		}

		writer, err := nbrew.FS.OpenWriter(path.Join(sitePrefix, filePath), 0644)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		defer writer.Close()
		_, err = io.Copy(writer, strings.NewReader(request.Content))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		err = writer.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}

		site := Site{
			Title:      "",        // TODO: read site config.
			Favicon:    "",        // TODO: read site config.
			Lang:       "",        // TODO: read site config.
			Categories: nil,       // TODO: read site fs.
			CodeStyle:  "onedark", // TODO: read site config.
		}

		head, _, _ := strings.Cut(filePath, "/")
		switch head {
		case "pages":
			err := nbrew.generatePage(r.Context(), site, sitePrefix, filePath, response.Content)
			if err != nil {
				var templateErrors TemplateErrors
				var templateExecutionError *TemplateExecutionError
				if errors.As(err, &templateErrors) {
					var n int
					names := make([]string, 0, len(templateErrors))
					for name, errmsgs := range templateErrors {
						names = append(names, name)
						n += len(errmsgs)
					}
					slices.Sort(names)
					response.TemplateErrors = make([]string, 0, n)
					for _, name := range names {
						for _, errmsg := range templateErrors[name] {
							response.TemplateErrors = append(response.TemplateErrors, name+": "+errmsg)
						}
					}
				} else if errors.As(err, &templateExecutionError) {
					response.TemplateErrors = append(response.TemplateErrors, templateExecutionError.Error())
				} else {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
		case "posts":
			err := nbrew.generatePost(r.Context(), site, sitePrefix, filePath, response.Content)
			var templateErrors TemplateErrors
			var templateExecutionError *TemplateExecutionError
			if errors.As(err, &templateErrors) {
				var n int
				names := make([]string, 0, len(templateErrors))
				for name, errmsgs := range templateErrors {
					names = append(names, name)
					n += len(errmsgs)
				}
				slices.Sort(names)
				response.TemplateErrors = make([]string, 0, n)
				for _, name := range names {
					for _, errmsg := range templateErrors[name] {
						response.TemplateErrors = append(response.TemplateErrors, name+": "+errmsg)
					}
				}
			} else if errors.As(err, &templateExecutionError) {
				response.TemplateErrors = append(response.TemplateErrors, templateExecutionError.Error())
			} else {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		response.Status = "PostSuccess"
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}

func (nbrew *Notebrew) listRootDirectory(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string, modTime time.Time) {
	writeResponse := func(w http.ResponseWriter, r *http.Request, response fileResponse) {
		if sitePrefix == "" && nbrew.UsersDB != nil {
			authorizedForRootSite := false
			n := 0
			for _, site := range response.Sites {
				if site.Name == "" {
					authorizedForRootSite = true
					continue
				}
				response.Sites[n] = site
				n++
			}
			response.Sites = response.Sites[:n]
			if !authorizedForRootSite {
				response.Files = response.Files[:0]
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
		tmpl, err := template.New("list_root_directory.html").Funcs(funcMap).ParseFS(rootFS, "embed/list_root_directory.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		executeTemplate(w, r, modTime, tmpl, &response)
	}

	var response fileResponse
	if sitePrefix == "" && nbrew.UsersDB != nil {
		sites, err := sq.FetchAll(r.Context(), nbrew.UsersDB, sq.Query{
			Dialect: nbrew.UsersDialect,
			Format: "SELECT {*}" +
				" FROM site_user" +
				" JOIN site ON site.site_id = site_user.site_id" +
				" JOIN users ON users.user_id = site_user.site_id" +
				" LEFT JOIN site_owner ON site_owner.site_id = site_user.site_id" +
				" LEFT JOIN users AS owner ON owner.user_id = site_owner.user_id" +
				" WHERE users.username = {username}" +
				" ORDER BY site_prefix",
			Values: []any{
				sq.StringParam("username", username),
			},
		}, func(row *sq.Row) siteEntry {
			return siteEntry{
				Name: row.String("CASE"+
					" WHEN site.site_name LIKE '%.%' THEN site.site_name"+
					" WHEN site.site_name <> '' THEN {concatSiteName}"+
					" ELSE ''"+
					" END AS site_prefix",
					sq.Param("concatSiteName", sq.DialectExpression{
						Default: sq.Expr("'@' || site.site_name"),
						Cases: []sq.DialectCase{{
							Dialect: "mysql",
							Result:  sq.Expr("concat('@', site.site_name)"),
						}},
					}),
				),
				Owner: row.String("owner.username"),
			}
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		response.Sites = sites
		n := slices.IndexFunc(response.Sites, func(site siteEntry) bool { return site.Name == "" })
		if n < 0 {
			writeResponse(w, r, response)
			return
		}
		copy(response.Sites[n:], response.Sites[n+1:])
		response.Sites = response.Sites[:len(response.Sites)-1]
	}

	remoteFS, ok := nbrew.FS.(*RemoteFS)
	if !ok {
		for _, name := range []string{"notes", "pages", "posts", "output/themes", "output"} {
			fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, name))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			if !fileInfo.IsDir() {
				continue
			}
			response.Files = append(response.Files, fileEntry{
				Name:    name,
				ModTime: fileInfo.ModTime(),
				IsDir:   true,
			})
		}

		if sitePrefix != "" || nbrew.UsersDB != nil {
			writeResponse(w, r, response)
			return
		}

		dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(".")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		for _, dirEntry := range dirEntries {
			if !dirEntry.IsDir() {
				continue
			}
			name := dirEntry.Name()
			if strings.HasPrefix(name, "@") || strings.Contains(name, ".") {
				response.Sites = append(response.Sites, siteEntry{Name: name})
			}
		}
		return
	}

	files, err := sq.FetchAll(r.Context(), remoteFS.filesDB, sq.Query{
		Dialect: remoteFS.filesDialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE file_path IN ({notes}, {pages}, {posts}, {themes}, {output})" +
			" AND is_dir" +
			" ORDER BY CASE file_path" +
			" WHEN {notes} THEN 1" +
			" WHEN {pages} THEN 2" +
			" WHEN {posts} THEN 3" +
			" WHEN {themes} THEN 4" +
			" WHEN {output} THEN 5" +
			" END",
		Values: []any{
			sq.StringParam("notes", path.Join(sitePrefix, "notes")),
			sq.StringParam("pages", path.Join(sitePrefix, "pages")),
			sq.StringParam("posts", path.Join(sitePrefix, "posts")),
			sq.StringParam("themes", path.Join(sitePrefix, "output/themes")),
			sq.StringParam("output", path.Join(sitePrefix, "output")),
		},
	}, func(row *sq.Row) fileEntry {
		return fileEntry{
			Name:    strings.Trim(strings.TrimPrefix(row.String("file_path"), sitePrefix), "/"),
			ModTime: row.Time("mod_time"),
			IsDir:   true,
		}
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	response.Files = files

	if sitePrefix != "" || nbrew.UsersDB != nil {
		writeResponse(w, r, response)
		return
	}

	from := r.FormValue("from")
	before := r.FormValue("before")
	response.Limit, _ = strconv.Atoi(r.FormValue("limit"))
	if response.Limit <= 0 {
		response.Limit = 1000
	}

	if from != "" {
		g, ctx := errgroup.WithContext(r.Context())
		g.Go(func() error {
			sites, err := sq.FetchAll(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' OR file_path LIKE %.%')" +
					" AND file_path >= {from}" +
					" ORDER BY file_path" +
					" LIMIT {limit} + 1",
				Values: []any{
					sq.StringParam("from", from),
					sq.IntParam("limit", response.Limit),
				},
			}, func(row *sq.Row) siteEntry {
				return siteEntry{
					Name:  row.String("files.file_path"),
					Owner: row.String("owner.username"),
				}
			})
			if err != nil {
				return err
			}
			response.Sites = sites
			if len(response.Sites) > response.Limit {
				response.NextSite = response.Sites[response.Limit].Name
				response.Sites = response.Sites[:response.Limit]
			}
			return nil
		})
		g.Go(func() error {
			hasPreviousSite, err := sq.FetchExists(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format:  "SELECT 1 FROM files WHERE file_path < {from}",
				Values: []any{
					sq.StringParam("from", from),
				},
			})
			if err != nil {
				return err
			}
			response.HasPreviousSite = hasPreviousSite
			return nil
		})
		err = g.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
		return
	}

	if before != "" {
		g, ctx := errgroup.WithContext(r.Context())
		err := g.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		g.Go(func() error {
			response.Sites, err = sq.FetchAll(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' OR file_path LIKE %.%')" +
					" AND file_path < {before}" +
					" ORDER BY file_path" +
					" LIMIT {limit} + 1",
				Values: []any{
					sq.StringParam("from", from),
					sq.IntParam("limit", response.Limit),
				},
			}, func(row *sq.Row) siteEntry {
				return siteEntry{
					Name:  row.String("files.file_path"),
					Owner: row.String("owner.username"),
				}
			})
			if err != nil {
				return err
			}
			if len(response.Sites) > response.Limit {
				response.HasPreviousFile = true
				response.Sites = response.Sites[1:]
			}
			return nil
		})
		g.Go(func() error {
			nextSite, err := sq.FetchOne(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format:  "SELECT {*} FROM files WHERE file_path = {before} ORDER BY file_path LIMIT 1",
				Values: []any{
					sq.StringParam("from", from),
				},
			}, func(row *sq.Row) string {
				return row.String("file_path")
			})
			if err != nil {
				return err
			}
			response.NextSite = nextSite
			return nil
		})
		err = g.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
		return
	}

	sites, err := sq.FetchAll(r.Context(), remoteFS.filesDB, sq.Query{
		Dialect: remoteFS.filesDialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE parent_id IS NULL" +
			" AND is_dir" +
			" AND (file_path LIKE '@%' OR file_path LIKE %.%')" +
			" ORDER BY file_path" +
			" LIMIT {limit} + 1",
		Values: []any{
			sq.IntParam("limit", response.Limit),
		},
	}, func(row *sq.Row) siteEntry {
		return siteEntry{
			Name:  row.String("files.file_path"),
			Owner: row.String("owner.username"),
		}
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	response.Sites = sites
	if len(response.Sites) > response.Limit {
		response.NextSite = response.Sites[response.Limit].Name
		response.Sites = response.Sites[:response.Limit]
	}
	writeResponse(w, r, response)
	return
}

// TODO: copy over directory.go into listDirectory().
func (nbrew *Notebrew) listDirectory(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string, modTime time.Time) {
	// sort=x&order=y&from=z
}

func (nbrew *Notebrew) generatePage(ctx context.Context, site Site, sitePrefix, filePath, content string) error {
	urlPath := strings.TrimPrefix(filePath, "pages/")
	if urlPath == "index.html" {
		urlPath = ""
	} else {
		urlPath = strings.TrimSuffix(urlPath, path.Ext(urlPath))
	}
	outputDir := path.Join(sitePrefix, "output", urlPath)
	pageData := PageData{
		Site:             site,
		Parent:           path.Dir(urlPath),
		Name:             path.Base(urlPath),
		ModificationTime: time.Now().UTC(),
	}
	if pageData.Parent == "." {
		pageData.Parent = ""
	}
	var err error
	var tmpl *template.Template
	g1, ctx1 := errgroup.WithContext(ctx)
	g1.Go(func() error {
		tmpl, err = NewTemplateParser(nbrew.FS, sitePrefix).ParseTemplate(ctx1, strings.TrimPrefix(filePath, "pages/"), content, nil)
		if err != nil {
			return err
		}
		return nil
	})
	g1.Go(func() error {
		markdownMu := sync.Mutex{}
		markdown := goldmark.New(
			goldmark.WithParserOptions(parser.WithAttribute()),
			goldmark.WithExtensions(
				extension.Table,
				highlighting.NewHighlighting(highlighting.WithStyle(pageData.Site.CodeStyle)),
			),
			goldmark.WithRendererOptions(goldmarkhtml.WithUnsafe()),
		)
		if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
			cursor, err := sq.FetchCursor(ctx1, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {outputDir})" +
					" AND NOT is_dir" +
					" AND (" +
					"file_path LIKE '%.jpeg'" +
					" OR file_path LIKE '%.jpg'" +
					" OR file_path LIKE '%.png'" +
					" OR file_path LIKE '%.webp'" +
					" OR file_path LIKE '%.gif'" +
					" OR file_path LIKE '%.md'" +
					") " +
					" ORDER BY file_path",
				Values: []any{
					sq.StringParam("outputDir", outputDir),
				},
			}, func(row *sq.Row) *RemoteFile {
				file := &RemoteFile{
					ctx: ctx1,
				}
				file.info.filePath = row.String("file_path")
				buf := bufPool.Get().(*bytes.Buffer)
				buf.Reset()
				b := buf.Bytes()
				row.Scan(&b, "CASE WHEN file_path LIKE '%.md' THEN text ELSE NULL END")
				if b != nil {
					file.buf = bytes.NewBuffer(b)
				}
				return file
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			g2, ctx2 := errgroup.WithContext(ctx1)
			for cursor.Next() {
				file, err := cursor.Result()
				if err != nil {
					return err
				}
				name := path.Base(file.info.filePath)
				switch path.Ext(file.info.filePath) {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					pageData.Images = append(pageData.Images, Image{Parent: urlPath, Name: name})
				case ".md":
					g2.Go(func() error {
						err := ctx2.Err()
						if err != nil {
							return err
						}
						defer file.Close()
						var b strings.Builder
						err = markdown.Convert(file.buf.Bytes(), &b)
						if err != nil {
							return err
						}
						markdownMu.Lock()
						pageData.Markdown[name] = template.HTML(b.String())
						markdownMu.Unlock()
						return nil
					})
				}
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
			err = g2.Wait()
			if err != nil {
				return err
			}
		} else {
			dirEntries, err := nbrew.FS.WithContext(ctx1).ReadDir(outputDir)
			if err != nil {
				return err
			}
			g2, ctx2 := errgroup.WithContext(ctx1)
			for _, dirEntry := range dirEntries {
				dirEntry := dirEntry
				name := dirEntry.Name()
				switch path.Ext(name) {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					pageData.Images = append(pageData.Images, Image{Parent: urlPath, Name: name})
				case ".md":
					g2.Go(func() error {
						file, err := nbrew.FS.WithContext(ctx2).Open(path.Join(outputDir, name))
						if err != nil {
							return err
						}
						defer file.Close()
						buf := bufPool.Get().(*bytes.Buffer)
						buf.Reset()
						defer func() {
							if buf.Cap() <= maxPoolableBufferCapacity {
								bufPool.Put(buf)
							}
						}()
						_, err = buf.ReadFrom(file)
						if err != nil {
							return err
						}
						var b strings.Builder
						err = markdown.Convert(buf.Bytes(), &b)
						if err != nil {
							return err
						}
						markdownMu.Lock()
						pageData.Markdown[name] = template.HTML(b.String())
						markdownMu.Unlock()
						return nil
					})
				}
			}
			err = g2.Wait()
			if err != nil {
				return err
			}
		}
		return nil
	})
	g1.Go(func() error {
		pageDir := path.Join(sitePrefix, "pages", urlPath)
		if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
			pageData.ChildPages, err = sq.FetchAll(ctx1, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {pageDir})" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.html'" +
					" ORDER BY file_path",
			}, func(row *sq.Row) Page {
				page := Page{
					Parent: urlPath,
					Name:   path.Base(row.String("file_path")),
				}
				line := strings.TrimSpace(row.String("{}", sq.DialectExpression{
					Default: sq.Expr("substr(text, 1, instr(text, char(10))-1)"),
					Cases: []sq.DialectCase{{
						Dialect: "postgres",
						Result:  sq.Expr("split_part(text, chr(10), 1)"),
					}, {
						Dialect: "mysql",
						Result:  sq.Expr("substring_index(text, char(10), 1)"),
					}},
				}))
				if !strings.HasPrefix(line, "<!--") {
					return page
				}
				line = strings.TrimSpace(strings.TrimPrefix(line, "<!--"))
				if !strings.HasPrefix(line, "#title") {
					return page
				}
				line = strings.TrimSpace(strings.TrimPrefix(line, "#title"))
				n := strings.Index(line, "-->")
				if n < 0 {
					return page
				}
				page.Title = strings.TrimSpace(line[:n])
				return page
			})
			if err != nil {
				return err
			}
		} else {
			dirEntries, err := nbrew.FS.WithContext(ctx1).ReadDir(pageDir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			pageData.ChildPages = make([]Page, len(dirEntries))
			g2, ctx2 := errgroup.WithContext(ctx1)
			for i, dirEntry := range dirEntries {
				i, dirEntry := i, dirEntry
				g2.Go(func() error {
					name := dirEntry.Name()
					if dirEntry.IsDir() || !strings.HasSuffix(name, ".html") {
						return nil
					}
					pageData.ChildPages[i].Parent = urlPath
					pageData.ChildPages[i].Name = name
					file, err := nbrew.FS.WithContext(ctx2).Open(path.Join(pageDir, name))
					if err != nil {
						return err
					}
					defer file.Close()
					reader := readerPool.Get().(*bufio.Reader)
					reader.Reset(file)
					defer readerPool.Put(reader)
					done := false
					for !done {
						line, err := reader.ReadSlice('\n')
						if err != nil {
							if err != io.EOF {
								return err
							}
							done = true
						}
						line = bytes.TrimSpace(line)
						if !bytes.HasPrefix(line, []byte("<!--")) {
							break
						}
						line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("<!--")))
						if !bytes.HasPrefix(line, []byte("#title")) {
							break
						}
						line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("#title")))
						n := bytes.Index(line, []byte("-->"))
						if n < 0 {
							break
						}
						pageData.ChildPages[i].Title = string(bytes.TrimSpace(line[:n]))
					}
					return nil
				})
			}
			err = g2.Wait()
			if err != nil {
				return err
			}
			n := 0
			for _, childPage := range pageData.ChildPages {
				if childPage != (Page{}) {
					pageData.ChildPages[n] = childPage
					n++
				}
			}
			pageData.ChildPages = pageData.ChildPages[:n]
		}
		return nil
	})
	err = g1.Wait()
	if err != nil {
		return err
	}
	writer, err := nbrew.FS.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		err := nbrew.FS.WithContext(ctx).MkdirAll(outputDir, 0755)
		if err != nil {
			return err
		}
		writer, err = nbrew.FS.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
		if err != nil {
			return err
		}
	}
	defer writer.Close()
	// TODO: stream template output into a pipeWriter, pass the pipeReader end
	// into a golang.org/x/net/html.Tokenizer and iterate over tokens, looking
	// for anchor tags and rewriting their href attribute to a CDN version if
	// applicable.
	err = tmpl.Execute(writer, &pageData)
	if err != nil {
		return &TemplateExecutionError{Err: err}
	}
	err = writer.Close()
	if err != nil {
		return err
	}
	return nil
}

func (nbrew *Notebrew) generatePost(ctx context.Context, site Site, sitePrefix, filePath, content string) error {
	urlPath := strings.TrimSuffix(filePath, path.Ext(filePath))
	outputDir := path.Join(sitePrefix, "output", urlPath)
	postData := PostData{
		Site:             site,
		Category:         path.Dir(strings.TrimPrefix(urlPath, "posts/")),
		Name:             path.Base(strings.TrimPrefix(urlPath, "posts/")),
		ModificationTime: time.Now().UTC(),
	}
	if strings.Contains(postData.Category, "/") {
		return nil
	}
	if postData.Category == "." {
		postData.Category = ""
	}
	prefix, _, ok := strings.Cut(strings.TrimPrefix(urlPath, "posts/"), "-")
	if !ok || len(prefix) == 0 || len(prefix) > 8 {
		return nil
	}
	b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
	if len(b) != 5 {
		return nil
	}
	var timestamp [8]byte
	copy(timestamp[len(timestamp)-5:], b)
	postData.CreationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)
	var err error
	var tmpl *template.Template
	g1, ctx1 := errgroup.WithContext(ctx)
	g1.Go(func() error {
		var err error
		var text sql.NullString
		if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
			text, err = sq.FetchOne(ctx1, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
				Values: []any{
					sq.StringParam("filePath", path.Join(sitePrefix, "output/themes/post.html")),
				},
			}, func(row *sq.Row) sql.NullString {
				return row.NullString("text")
			})
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		} else {
			file, err := nbrew.FS.WithContext(ctx1).Open(path.Join(sitePrefix, "output/themes/post.html"))
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			} else {
				defer file.Close()
				fileInfo, err := file.Stat()
				if err != nil {
					return err
				}
				if fileInfo.IsDir() {
					return fmt.Errorf("%s is not a file", filePath)
				}
				var b strings.Builder
				b.Grow(int(fileInfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					return err
				}
				err = file.Close()
				if err != nil {
					return err
				}
				text = sql.NullString{String: b.String(), Valid: true}
			}
		}
		if !text.Valid {
			file, err := rootFS.Open("embed/post.html")
			if err != nil {
				return err
			}
			fileInfo, err := file.Stat()
			if err != nil {
				return err
			}
			if fileInfo.IsDir() {
				return fmt.Errorf("%s is not a file", filePath)
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return err
			}
			err = file.Close()
			if err != nil {
				return err
			}
			text = sql.NullString{String: b.String(), Valid: true}
		}
		tmpl, err = NewTemplateParser(nbrew.FS, sitePrefix).ParseTemplate(ctx1, "/themes/post.html", text.String, []string{"/themes/post.html"})
		if err != nil {
			return err
		}
		return nil
	})
	g1.Go(func() error {
		err := ctx1.Err()
		if err != nil {
			return err
		}
		markdown := goldmark.New(
			goldmark.WithParserOptions(parser.WithAttribute()),
			goldmark.WithExtensions(
				extension.Table,
				highlighting.NewHighlighting(highlighting.WithStyle(site.CodeStyle)),
			),
			goldmark.WithRendererOptions(goldmarkhtml.WithUnsafe()),
		)
		contentBytes := []byte(content)
		// Title
		var line []byte
		remainder := contentBytes
		for len(remainder) > 0 {
			line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			postData.Title = stripMarkdownStyles(line)
			break
		}
		// Content
		var b strings.Builder
		err = markdown.Convert(contentBytes, &b)
		if err != nil {
			return err
		}
		postData.Content = template.HTML(b.String())
		return nil
	})
	g1.Go(func() error {
		if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
			cursor, err := sq.FetchCursor(ctx1, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {outputDir})" +
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
					sq.StringParam("outputDir", outputDir),
				},
			}, func(row *sq.Row) string {
				return path.Base(row.String("file_path"))
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			for cursor.Next() {
				name, err := cursor.Result()
				if err != nil {
					return err
				}
				postData.Images = append(postData.Images, Image{Parent: urlPath, Name: name})
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
		} else {
			dirEntries, err := nbrew.FS.WithContext(ctx1).ReadDir(outputDir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			for _, dirEntry := range dirEntries {
				name := dirEntry.Name()
				if dirEntry.IsDir() {
					continue
				}
				switch path.Ext(name) {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					postData.Images = append(postData.Images, Image{Parent: urlPath, Name: name})
				}
			}
		}
		return nil
	})
	err = g1.Wait()
	if err != nil {
		return err
	}
	writer, err := nbrew.FS.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		err := nbrew.FS.WithContext(ctx).MkdirAll(outputDir, 0755)
		if err != nil {
			return err
		}
		writer, err = nbrew.FS.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
		if err != nil {
			return err
		}
	}
	defer writer.Close()
	// TODO: stream template output into a pipeWriter, pass the pipeReader end
	// into a golang.org/x/net/html.Tokenizer and iterate over tokens, looking
	// for anchor tags and rewriting their href attribute to a CDN version if
	// applicable.
	err = tmpl.Execute(writer, &postData)
	if err != nil {
		return &TemplateExecutionError{Err: err}
	}
	err = writer.Close()
	if err != nil {
		return err
	}
	return nil
}
