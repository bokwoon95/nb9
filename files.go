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
	"mime"
	"net/http"
	"net/url"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/nb9/sq"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) files(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string) {
	type Asset struct {
		Name         string    `json:"name"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size"`
	}
	type Response struct {
		PostRedirectGet map[string]any `json:"postRedirectGet,omitempty"`
		TemplateErrors  []string       `json:"templateErrors,omitempty"`
		ContentSite     string         `json:"contentSite"`
		Username        NullString     `json:"username"`
		SitePrefix      string         `json:"sitePrefix"`
		FilePath        string         `json:"filePath"`
		IsDir           bool           `json:"isDir"`
		ModTime         time.Time      `json:"modTime"`
		CreationTime    time.Time      `json:"creationTime"`
		Content         string         `json:"content"`
		URL             string         `json:"url,omitempty"`
		BelongsTo       string         `json:"belongsTo,omitempty"`
		AssetDir        string         `json:"assetDir,omitempty"`
		Assets          []Asset        `json:"assets,omitempty"`
	}

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
			nbrew.listRootDirectory(w, r, username, sitePrefix, fileInfo.ModTime())
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
		if tail != "index.html" {
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
		}
	default:
		notFound(w, r)
		return
	}

	switch r.Method {
	case "GET":
		var response Response
		_, err = nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentSite = nbrew.contentSite(sitePrefix)
		response.Username = NullString{String: username, Valid: nbrew.UsersDB != nil}
		response.SitePrefix = sitePrefix
		response.FilePath = filePath
		response.IsDir = fileInfo.IsDir()
		response.ModTime = fileInfo.ModTime()
		if fileInfo, ok := fileInfo.(*remoteFileInfo); ok {
			response.CreationTime = fileInfo.creationTime
		} else if runtime.GOOS == "linux" {
			if localFS, ok := nbrew.FS.(*LocalFS); ok {
				response.CreationTime = getCreationTime(path.Join(localFS.rootDir, sitePrefix, response.FilePath), nil)
			}
		} else {
			response.CreationTime = getCreationTime("", fileInfo)
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
				}, func(row *sq.Row) Asset {
					return Asset{
						Name:         path.Base(row.String("file_path")),
						Size:         row.Int64("size"),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
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
						asset := Asset{
							Name:    name,
							Size:    fileInfo.Size(),
							ModTime: fileInfo.ModTime(),
						}
						if runtime.GOOS == "linux" {
							if localFS, ok := nbrew.FS.(*LocalFS); ok {
								asset.CreationTime = getCreationTime(path.Join(localFS.rootDir, sitePrefix, response.AssetDir, asset.Name), nil)
							}
						} else {
							asset.CreationTime = getCreationTime("", fileInfo)
						}
						response.Assets = append(response.Assets, asset)
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
				}, func(row *sq.Row) Asset {
					return Asset{
						Name:         path.Base(row.String("file_path")),
						Size:         row.Int64("size"),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
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
						asset := Asset{
							Name:    name,
							Size:    fileInfo.Size(),
							ModTime: fileInfo.ModTime(),
						}
						if runtime.GOOS == "linux" {
							if localFS, ok := nbrew.FS.(*LocalFS); ok {
								asset.CreationTime = getCreationTime(path.Join(localFS.rootDir, sitePrefix, response.AssetDir, asset.Name), nil)
							}
						} else {
							asset.CreationTime = getCreationTime("", fileInfo)
						}
						response.Assets = append(response.Assets, asset)
					}
				}
			}
		case "output":
			if isEditable {
				n := strings.Index(tail, "/")
				if tail[:n] != "posts" && tail[:n] != "themes" {
					response.BelongsTo = path.Join("pages", path.Dir(tail)+".html")
				}
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
			"trimSuffix":       strings.TrimSuffix,
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
		tmpl, err := template.New("file.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/file.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		executeTemplate(w, r, tmpl, &response)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
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
			response.PostRedirectGet = map[string]any{
				"from": "files",
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
			Content string
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
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
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
				if err != nil {
					badRequest(w, r, err)
					return
				}
			} else {
				err := r.ParseForm()
				if err != nil {
					badRequest(w, r, err)
					return
				}
			}
			request.Content = r.FormValue("content")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			ContentSite: nbrew.contentSite(sitePrefix),
			Username:    NullString{String: username, Valid: nbrew.UsersDB != nil},
			SitePrefix:  sitePrefix,
			FilePath:    filePath,
			IsDir:       fileInfo.IsDir(),
			ModTime:     fileInfo.ModTime(),
			Content:     request.Content,
		}
		if fileInfo, ok := fileInfo.(*remoteFileInfo); ok {
			response.CreationTime = fileInfo.creationTime
		} else if runtime.GOOS == "linux" {
			if localFS, ok := nbrew.FS.(*LocalFS); ok {
				response.CreationTime = getCreationTime(path.Join(localFS.rootDir, sitePrefix, response.FilePath), nil)
			}
		} else {
			response.CreationTime = getCreationTime("", fileInfo)
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

		siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.CDNDomain)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		head, _, _ := strings.Cut(filePath, "/")
		switch head {
		case "pages":
			err := siteGen.GeneratePage(r.Context(), filePath, response.Content)
			if err != nil {
				var parseErr TemplateParseError
				var executionErr *TemplateExecutionError
				if errors.As(err, &parseErr) {
					response.TemplateErrors = append(response.TemplateErrors, parseErr.List()...)
				} else if errors.As(err, &executionErr) {
					response.TemplateErrors = append(response.TemplateErrors, executionErr.Err.Error())
				} else {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
		case "posts":
			tmpl, err := siteGen.PostTemplate(r.Context())
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			err = siteGen.GeneratePost(r.Context(), filePath, response.Content, tmpl)
			if err != nil {
				var parseErr TemplateParseError
				var executionErr *TemplateExecutionError
				if errors.As(err, &parseErr) {
					response.TemplateErrors = append(response.TemplateErrors, parseErr.List()...)
				} else if errors.As(err, &executionErr) {
					response.TemplateErrors = append(response.TemplateErrors, executionErr.Error())
				} else {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
		}
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}

func (nbrew *Notebrew) listRootDirectory(w http.ResponseWriter, r *http.Request, username, sitePrefix string, modTime time.Time) {
	type File struct {
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size,omitempty"`
	}
	type Site struct {
		Name  string `json:"name"`
		Owner string `json:"owner,omitempty"`
	}
	type Response struct {
		PostRedirectGet map[string]any `json:"postRedirectGet,omitempty"`
		ContentSite     string         `json:"contentSite"`
		Username        NullString     `json:"username"`
		SitePrefix      string         `json:"sitePrefix"`
		FilePath        string         `json:"filePath"`
		IsDir           bool           `json:"isDir"`
		SearchSupported bool           `json:"searchSupported"`

		Files []File `json:"files,omitempty"`

		From               string `json:"from,omitempty"`
		Before             string `json:"before,omitempty"`
		Limit              int    `json:"limit"`
		Sites              []Site `json:"sites"`
		PreviousSiteExists bool   `json:"previousSiteExists,omitempty"`
		NextSite           string `json:"nextSite,omitempty"`
	}
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
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
		clipboard := make(url.Values)
		isInClipboard := make(map[string]bool)
		cookie, _ := r.Cookie("clipboard")
		if cookie != nil {
			values, err := url.ParseQuery(cookie.Value)
			if err == nil {
				if values.Has("cut") {
					clipboard.Set("cut", "")
				}
				clipboard.Set("sitePrefix", values.Get("sitePrefix"))
				clipboard.Set("parent", values.Get("parent"))
				for _, name := range values["name"] {
					if isInClipboard[name] {
						continue
					}
					clipboard.Add("name", name)
					isInClipboard[name] = true
				}
			}
		}
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
			"directoryJS":      func() template.JS { return template.JS(directoryJS) },
			"referer":          func() string { return referer },
			"clipboard":        func() url.Values { return clipboard },
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
		tmpl, err := template.New("list_root_directory.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/list_root_directory.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		executeTemplate(w, r, tmpl, &response)
	}

	var response Response
	_, err := nbrew.getSession(r, "flash", &response)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	}
	nbrew.clearSession(w, r, "flash")
	response.ContentSite = nbrew.contentSite(sitePrefix)
	response.Username = NullString{String: username, Valid: nbrew.UsersDB != nil}
	response.SitePrefix = sitePrefix
	response.IsDir = true
	response.Sites = []Site{}
	_, response.SearchSupported = nbrew.FS.(*RemoteFS)
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
		}, func(row *sq.Row) Site {
			return Site{
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
		n := slices.IndexFunc(response.Sites, func(site Site) bool { return site.Name == "" })
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
			file := File{
				Name:    name,
				ModTime: fileInfo.ModTime(),
				IsDir:   true,
			}
			if runtime.GOOS == "linux" {
				if localFS, ok := nbrew.FS.(*LocalFS); ok {
					file.CreationTime = getCreationTime(path.Join(localFS.rootDir, sitePrefix, name, file.Name), nil)
				}
			} else {
				file.CreationTime = getCreationTime("", fileInfo)
			}
			response.Files = append(response.Files, file)
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
				response.Sites = append(response.Sites, Site{Name: name})
			}
		}
		writeResponse(w, r, response)
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
	}, func(row *sq.Row) File {
		return File{
			Name:         strings.Trim(strings.TrimPrefix(row.String("file_path"), sitePrefix), "/"),
			ModTime:      row.Time("mod_time"),
			CreationTime: row.Time("creation_time"),
			IsDir:        true,
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

	response.Limit, _ = strconv.Atoi(r.FormValue("limit"))
	if response.Limit <= 0 {
		response.Limit = 1000
	}

	response.From = r.FormValue("from")
	if response.From != "" {
		g, ctx := errgroup.WithContext(r.Context())
		g.Go(func() error {
			sites, err := sq.FetchAll(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' OR file_path LIKE '%.%')" +
					" AND file_path >= {from}" +
					" ORDER BY file_path" +
					" LIMIT {limit} + 1",
				Values: []any{
					sq.StringParam("from", response.From),
					sq.IntParam("limit", response.Limit),
				},
			}, func(row *sq.Row) Site {
				return Site{
					Name: row.String("files.file_path"),
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
				Format: "SELECT 1" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' OR file_path LIKE '%.%')" +
					" AND file_path < {from}",
				Values: []any{
					sq.StringParam("from", response.From),
				},
			})
			if err != nil {
				return err
			}
			response.PreviousSiteExists = hasPreviousSite
			return nil
		})
		err := g.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
		return
	}

	response.Before = r.FormValue("before")
	if response.Before != "" {
		g, ctx := errgroup.WithContext(r.Context())
		g.Go(func() error {
			response.Sites, err = sq.FetchAll(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' OR file_path LIKE '%.%')" +
					" AND file_path < {before}" +
					" ORDER BY file_path" +
					" LIMIT {limit} + 1",
				Values: []any{
					sq.StringParam("before", response.Before),
					sq.IntParam("limit", response.Limit),
				},
			}, func(row *sq.Row) Site {
				return Site{
					Name: row.String("files.file_path"),
				}
			})
			if err != nil {
				return err
			}
			if len(response.Sites) > response.Limit {
				response.PreviousSiteExists = true
				response.Sites = response.Sites[1:]
			}
			return nil
		})
		g.Go(func() error {
			nextSite, err := sq.FetchOne(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND file_path >= {before}" +
					" ORDER BY file_path" +
					" LIMIT 1",
				Values: []any{
					sq.StringParam("before", response.Before),
				},
			}, func(row *sq.Row) string {
				return row.String("file_path")
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil
				}
				return err
			}
			response.NextSite = nextSite
			return nil
		})
		err := g.Wait()
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
			" AND (file_path LIKE '@%' OR file_path LIKE '%.%')" +
			" ORDER BY file_path" +
			" LIMIT {limit} + 1",
		Values: []any{
			sq.IntParam("limit", response.Limit),
		},
	}, func(row *sq.Row) Site {
		return Site{
			Name: row.String("files.file_path"),
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

// copied from https://pkg.go.dev/github.com/mattn/go-sqlite3#pkg-variables
var timestampFormats = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02T15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04",
	"2006-01-02T15:04",
	"2006-01-02",
}

func (nbrew *Notebrew) listDirectory(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string, modTime time.Time) {
	type File struct {
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size,omitempty"`
	}
	type Response struct {
		PostRedirectGet map[string]any `json:"postRedirectGet,omitempty"`
		ContentSite     string         `json:"contentSite"`
		Username        NullString     `json:"username"`
		SitePrefix      string         `json:"sitePrefix"`
		FilePath        string         `json:"filePath"`
		IsDir           bool           `json:"isDir"`
		ModTime         time.Time      `json:"modTime"`
		CreationTime    time.Time      `json:"creationTime"`
		SearchSupported bool           `json:"searchSupported"`

		Sort               string `json:"sort,omitempty"`
		Order              string `json:"order,omitempty"`
		From               string `json:"from,omitempty"`
		Before             string `json:"before,omitempty"`
		Limit              int    `json:"limit,omitempty"`
		Files              []File `json:"files,omitempty"`
		PreviousFileExists bool   `json:"previousFileExists,omitempty"`
		NextFile           string `json:"nextFile,omitempty"`
	}
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
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
		clipboard := make(url.Values)
		isInClipboard := make(map[string]bool)
		cookie, _ := r.Cookie("clipboard")
		if cookie != nil {
			values, err := url.ParseQuery(cookie.Value)
			if err == nil {
				if values.Has("cut") {
					clipboard.Set("cut", "")
				}
				clipboard.Set("sitePrefix", values.Get("sitePrefix"))
				clipboard.Set("parent", values.Get("parent"))
				for _, name := range values["name"] {
					if isInClipboard[name] {
						continue
					}
					clipboard.Add("name", name)
					isInClipboard[name] = true
				}
			}
		}
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
			"directoryJS":      func() template.JS { return template.JS(directoryJS) },
			"referer":          func() string { return referer },
			"clipboard":        func() url.Values { return clipboard },
			"safeHTML":         func(s string) template.HTML { return template.HTML(s) },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
			"generateBreadcrumbLinks": func(sitePrefix, filePath string) template.HTML {
				var b strings.Builder
				b.WriteString("<a href='/files/'>files</a>")
				segments := strings.Split(filePath, "/")
				if sitePrefix != "" {
					segments = append([]string{sitePrefix}, segments...)
				}
				for i := 0; i < len(segments); i++ {
					if segments[i] == "" {
						continue
					}
					href := "/files/" + path.Join(segments[:i+1]...) + "/"
					b.WriteString(" / <a href='" + href + "'>" + segments[i] + "</a>")
				}
				b.WriteString(" /")
				return template.HTML(b.String())
			},
			"isInClipboard": func(name string) bool {
				if sitePrefix != clipboard.Get("sitePrefix") {
					return false
				}
				if response.FilePath != clipboard.Get("parent") {
					return false
				}
				return isInClipboard[name]
			},
		}
		tmpl, err := template.New("list_directory.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/list_directory.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		executeTemplate(w, r, tmpl, &response)
	}

	head, _, _ := strings.Cut(filePath, "/")
	if head != "notes" && head != "pages" && head != "posts" && head != "output" {
		notFound(w, r)
		return
	}

	var response Response
	_, err := nbrew.getSession(r, "flash", &response)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	}
	nbrew.clearSession(w, r, "flash")
	response.ContentSite = nbrew.contentSite(sitePrefix)
	response.Username = NullString{String: username, Valid: nbrew.UsersDB != nil}
	response.SitePrefix = sitePrefix
	response.FilePath = filePath
	response.IsDir = true
	_, response.SearchSupported = nbrew.FS.(*RemoteFS)
	response.Sort = strings.ToLower(strings.TrimSpace(r.FormValue("sort")))
	if response.Sort == "" {
		cookie, _ := r.Cookie("sort")
		if cookie != nil {
			response.Sort = cookie.Value
		}
	}
	switch response.Sort {
	case "name", "edited", "created":
		break
	default:
		if head == "posts" {
			response.Sort = "created"
		} else {
			response.Sort = "name"
		}
	}
	response.Order = strings.ToLower(strings.TrimSpace(r.Form.Get("order")))
	if response.Order == "" {
		cookie, _ := r.Cookie("order")
		if cookie != nil {
			response.Order = cookie.Value
		}
	}
	switch response.Order {
	case "asc", "desc":
		break
	default:
		if response.Sort == "created" || response.Sort == "edited" {
			response.Order = "desc"
		} else {
			response.Order = "asc"
		}
	}

	remoteFS, ok := nbrew.FS.(*RemoteFS)
	if !ok {
		dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(path.Join(sitePrefix, filePath))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		for _, dirEntry := range dirEntries {
			fileInfo, err := dirEntry.Info()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			file := File{
				Name:    fileInfo.Name(),
				Size:    fileInfo.Size(),
				ModTime: fileInfo.ModTime(),
				IsDir:   fileInfo.IsDir(),
			}
			if runtime.GOOS == "linux" {
				if localFS, ok := nbrew.FS.(*LocalFS); ok {
					file.CreationTime = getCreationTime(path.Join(localFS.rootDir, sitePrefix, filePath, file.Name), nil)
				}
			} else {
				file.CreationTime = getCreationTime("", fileInfo)
			}
			if file.IsDir {
				response.Files = append(response.Files, file)
				continue
			}
			_, ok := fileTypes[path.Ext(file.Name)]
			if !ok {
				continue
			}
			response.Files = append(response.Files, file)
		}
		switch response.Sort {
		case "name":
			if response.Order == "desc" {
				slices.Reverse(response.Files)
			}
		case "edited":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.ModTime.Equal(b.ModTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.ModTime.Before(b.ModTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		case "created":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.CreationTime.Equal(b.CreationTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.CreationTime.Before(b.CreationTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		}
		writeResponse(w, r, response)
		return
	}

	response.Limit, _ = strconv.Atoi(r.FormValue("limit"))
	if response.Limit <= 0 {
		response.Limit = 1000
	}

	var sortFrom bool
	var fromTime time.Time
	response.From = r.FormValue("from")
	if response.Sort == "name" {
		sortFrom = response.From != ""
	} else if response.Sort == "edited" || response.Sort == "created" {
		response.From = strings.TrimSuffix(response.From, "Z")
		for _, format := range timestampFormats {
			timeVal, err := time.ParseInLocation(format, response.From, time.UTC)
			if err == nil {
				fromTime = timeVal
				sortFrom = true
				break
			}
		}
	}
	if sortFrom {
		g, ctx := errgroup.WithContext(r.Context())
		g.Go(func() error {
			var filter, order sq.Expression
			if response.Sort == "name" {
				if response.Order == "asc" {
					filter = sq.Expr("file_path >= {}", path.Join(sitePrefix, filePath, response.From))
					order = sq.Expr("file_path ASC")
				} else {
					filter = sq.Expr("file_path <= {}", path.Join(sitePrefix, filePath, response.From))
					order = sq.Expr("file_path DESC")
				}
			} else if response.Sort == "edited" {
				if response.Order == "asc" {
					filter = sq.Expr("mod_time >= {}", fromTime)
					order = sq.Expr("mod_time ASC, file_path")
				} else {
					filter = sq.Expr("mod_time <= {}", fromTime)
					order = sq.Expr("mod_time DESC, file_path")
				}
			} else if response.Sort == "created" {
				if response.Order == "asc" {
					filter = sq.Expr("creation_time >= {}", fromTime)
					order = sq.Expr("creation_time ASC, file_path")
				} else {
					filter = sq.Expr("creation_time <= {}", fromTime)
					order = sq.Expr("creation_time DESC, file_path")
				}
			}
			files, err := sq.FetchAll(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
					" AND {filter}" +
					" ORDER BY {order}" +
					" LIMIT {limit} + 1",
				Values: []any{
					sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
					sq.Param("filter", filter),
					sq.Param("order", order),
					sq.IntParam("limit", response.Limit),
				},
			}, func(row *sq.Row) File {
				return File{
					Name:    path.Base(row.String("files.file_path")),
					Size:    row.Int64("size"),
					ModTime: row.Time("mod_time"),
					IsDir:   row.Bool("is_dir"),
				}
			})
			if err != nil {
				return err
			}
			response.Files = files
			if len(response.Files) > response.Limit {
				nextFile := response.Files[response.Limit]
				response.Files = response.Files[:response.Limit]
				if response.Sort == "name" || response.Sort == "created" {
					response.NextFile = nextFile.Name
				} else if response.Sort == "edited" {
					response.NextFile = nextFile.ModTime.UTC().Format("2006-01-02T15:04:05Z")
				}
			}
			return nil
		})
		g.Go(func() error {
			var filter sq.Expression
			if response.Sort == "name" || response.Sort == "created" {
				if response.Order == "asc" {
					filter = sq.Expr("file_path < {}", path.Join(sitePrefix, filePath, response.From))
				} else {
					filter = sq.Expr("file_path > {}", path.Join(sitePrefix, filePath, response.From))
				}
			} else if response.Sort == "edited" {
				if response.Order == "asc" {
					filter = sq.Expr("mod_time < {}", fromTime)
				} else {
					filter = sq.Expr("mod_time > {}", fromTime)
				}
			}
			hasPreviousFile, err := sq.FetchExists(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT 1" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
					" AND {filter}",
				Values: []any{
					sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
					sq.Param("filter", filter),
				},
			})
			if err != nil {
				return err
			}
			response.PreviousFileExists = hasPreviousFile
			return nil
		})
		err := g.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
		return
	}

	var sortBefore bool
	var beforeTime time.Time
	response.Before = r.FormValue("before")
	if response.Sort == "name" || response.Sort == "created" {
		sortBefore = response.Before != ""
	} else if response.Sort == "edited" {
		response.Before = strings.TrimSuffix(response.Before, "Z")
		for _, format := range timestampFormats {
			timeVal, err := time.ParseInLocation(format, response.Before, time.UTC)
			if err == nil {
				beforeTime = timeVal
				sortBefore = true
				break
			}
		}
	}
	if sortBefore {
		g, ctx := errgroup.WithContext(r.Context())
		g.Go(func() error {
			var filter, order sq.Expression
			if response.Sort == "name" || response.Sort == "created" {
				if response.Order == "asc" {
					filter = sq.Expr("file_path < {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path ASC")
				} else {
					filter = sq.Expr("file_path > {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path DESC")
				}
			} else if response.Sort == "edited" {
				if response.Order == "asc" {
					filter = sq.Expr("mod_time < {}", beforeTime)
					order = sq.Expr("mod_time ASC, file_path")
				} else {
					filter = sq.Expr("mod_time > {}", beforeTime)
					order = sq.Expr("mod_time DESC, file_path")
				}
			}
			files, err := sq.FetchAll(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
					" AND {filter}" +
					" ORDER BY {order}" +
					" LIMIT {limit} + 1",
				Values: []any{
					sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
					sq.Param("filter", filter),
					sq.Param("order", order),
					sq.IntParam("limit", response.Limit),
				},
			}, func(row *sq.Row) File {
				return File{
					Name:    path.Base(row.String("file_path")),
					Size:    row.Int64("size"),
					ModTime: row.Time("mod_time"),
					IsDir:   row.Bool("is_dir"),
				}
			})
			if err != nil {
				return err
			}
			response.Files = files
			if len(response.Files) > response.Limit {
				response.PreviousFileExists = true
				response.Files = response.Files[1:]
			}
			return nil
		})
		g.Go(func() error {
			var filter, order sq.Expression
			if response.Sort == "name" || response.Sort == "created" {
				if response.Order == "asc" {
					filter = sq.Expr("file_path >= {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path ASC")
				} else {
					filter = sq.Expr("file_path <= {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path DESC")
				}
			} else if response.Sort == "edited" {
				if response.Order == "asc" {
					filter = sq.Expr("mod_time >= {}", beforeTime)
					order = sq.Expr("mod_time ASC, file_path")
				} else {
					filter = sq.Expr("mod_time <= {}", beforeTime)
					order = sq.Expr("mod_time DESC, file_path")
				}
			}
			nextFile, err := sq.FetchOne(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
					" AND {filter}" +
					" ORDER BY {order}" +
					" LIMIT 1",
				Values: []any{
					sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
					sq.Param("filter", filter),
					sq.Param("order", order),
				},
			}, func(row *sq.Row) File {
				return File{
					Name:    path.Base(row.String("file_path")),
					ModTime: row.Time("mod_time"),
				}
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil
				}
				return err
			}
			if response.Sort == "name" || response.Sort == "created" {
				response.NextFile = nextFile.Name
			} else if response.Sort == "edited" {
				response.NextFile = nextFile.ModTime.UTC().Format("2006-01-02T15:04:05Z")
			}
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

	var order sq.Expression
	if response.Sort == "name" || response.Sort == "created" {
		if response.Order == "asc" {
			order = sq.Expr("file_path ASC")
		} else {
			order = sq.Expr("file_path DESC")
		}
	} else if response.Sort == "edited" {
		if response.Order == "asc" {
			order = sq.Expr("mod_time ASC, file_path")
		} else {
			order = sq.Expr("mod_time DESC, file_path")
		}
	}
	files, err := sq.FetchAll(r.Context(), remoteFS.filesDB, sq.Query{
		Dialect: remoteFS.filesDialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
			" ORDER BY {order}" +
			" LIMIT {limit} + 1",
		Values: []any{
			sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
			sq.Param("order", order),
			sq.IntParam("limit", response.Limit),
		},
	}, func(row *sq.Row) File {
		return File{
			Name:    path.Base(row.String("file_path")),
			Size:    row.Int64("size"),
			ModTime: row.Time("mod_time"),
			IsDir:   row.Bool("is_dir"),
		}
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	response.Files = files
	if len(response.Files) > response.Limit {
		nextFile := response.Files[response.Limit]
		response.Files = response.Files[:response.Limit]
		if response.Sort == "name" || response.Sort == "created" {
			response.NextFile = nextFile.Name
		} else if response.Sort == "edited" {
			response.NextFile = nextFile.ModTime.UTC().Format("2006-01-02T15:04:05Z")
		}
	}
	writeResponse(w, r, response)
	return
}

func serveFile(w http.ResponseWriter, r *http.Request, file fs.File, fileInfo fs.FileInfo, fileType FileType, cacheControl string) {
	// .jpeg .jpg .png .webp .gif .woff .woff2
	if !fileType.IsGzippable {
		if fileSeeker, ok := file.(io.ReadSeeker); ok {
			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()
			_, err := io.Copy(hasher, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			_, err = fileSeeker.Seek(0, io.SeekStart)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var b [blake2b.Size256]byte
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", cacheControl)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
			http.ServeContent(w, r, "", fileInfo.ModTime(), fileSeeker)
			return
		}

		if fileInfo.Size() <= 1<<20 /* 1 MB */ {
			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()
			var buf *bytes.Buffer
			if fileInfo.Size() > maxPoolableBufferCapacity {
				buf = bytes.NewBuffer(make([]byte, 0, fileInfo.Size()))
			} else {
				buf = bufPool.Get().(*bytes.Buffer)
				defer func() {
					buf.Reset()
					bufPool.Put(buf)
				}()
			}
			multiWriter := io.MultiWriter(hasher, buf)
			_, err := io.Copy(multiWriter, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var b [blake2b.Size256]byte
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", cacheControl)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
			http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
			return
		}

		w.Header().Set("Content-Type", fileType.ContentType)
		w.Header().Set("Cache-Control", cacheControl)
		_, err := io.Copy(w, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}

	// .html .css .js .md .txt .svg .ico .eot .otf .ttf .atom .webmanifest

	if remoteFile, ok := file.(*RemoteFile); ok {
		// If file is a RemoteFile and is not fulltext indexed, its contents
		// are already gzipped. We can reach directly into its buffer and skip
		// the gzipping step.
		if !remoteFile.isFulltextIndexed {
			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()
			_, err := hasher.Write(remoteFile.buf.Bytes())
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var b [blake2b.Size256]byte
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", cacheControl)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
			http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(remoteFile.buf.Bytes()))
			return
		}
	}

	if fileInfo.Size() <= 1<<20 /* 1 MB */ {
		hasher := hashPool.Get().(hash.Hash)
		defer func() {
			hasher.Reset()
			hashPool.Put(hasher)
		}()
		var buf *bytes.Buffer
		// gzip will at least halve the size of what needs to be buffered
		gzippedSize := fileInfo.Size() >> 1
		if gzippedSize > maxPoolableBufferCapacity {
			buf = bytes.NewBuffer(make([]byte, 0, fileInfo.Size()))
		} else {
			buf = bufPool.Get().(*bytes.Buffer)
			defer func() {
				buf.Reset()
				bufPool.Put(buf)
			}()
		}
		multiWriter := io.MultiWriter(buf, hasher)
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(multiWriter)
		defer func() {
			gzipWriter.Reset(io.Discard)
			gzipWriterPool.Put(gzipWriter)
		}()
		_, err := io.Copy(gzipWriter, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		var b [blake2b.Size256]byte
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", fileType.ContentType)
		w.Header().Set("Cache-Control", cacheControl)
		w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
		http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
		return
	}

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", fileType.ContentType)
	w.Header().Set("Cache-Control", cacheControl)
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(w)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	_, err := io.Copy(gzipWriter, file)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	} else {
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
	}
}
