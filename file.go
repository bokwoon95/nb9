package nb9

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/nb9/sq"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) files(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string) {
	type Asset struct {
		FileID       [16]byte  `json:"-"`
		Name         string    `json:"name"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size"`
	}
	type Response struct {
		PostRedirectGet map[string]any `json:"postRedirectGet,omitempty"`
		TemplateError   TemplateError  `json:"templateError,omitempty"`
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
		FilesExist      []string       `json:"filesExist,omitempty"`
		FilesTooBig     []string       `json:"filesTooBig,omitempty"`
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
			nbrew.rootdirectory(w, r, username, sitePrefix, fileInfo.ModTime())
			return
		}
		nbrew.directory(w, r, username, sitePrefix, filePath, fileInfo.ModTime())
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
		if r.Form.Has("raw") {
			serveFile(w, r, file, fileInfo, fileType, "no-store")
			return
		}
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
		if fileInfo, ok := fileInfo.(*RemoteFileInfo); ok {
			response.CreationTime = fileInfo.CreationTime
		} else {
			var absolutePath string
			if localFS, ok := nbrew.FS.(*LocalFS); ok {
				absolutePath = path.Join(localFS.rootDir, sitePrefix, response.FilePath)
			}
			response.CreationTime = CreationTime(absolutePath, fileInfo)
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
						var absolutePath string
						if localFS, ok := nbrew.FS.(*LocalFS); ok {
							absolutePath = path.Join(localFS.rootDir, sitePrefix, response.AssetDir, name)
						}
						response.Assets = append(response.Assets, Asset{
							Name:         name,
							Size:         fileInfo.Size(),
							ModTime:      fileInfo.ModTime(),
							CreationTime: CreationTime(absolutePath, fileInfo),
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
				}, func(row *sq.Row) Asset {
					return Asset{
						FileID:       row.UUID("file_id"),
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
						var absolutePath string
						if localFS, ok := nbrew.FS.(*LocalFS); ok {
							absolutePath = path.Join(localFS.rootDir, sitePrefix, response.AssetDir, name)
						}
						response.Assets = append(response.Assets, Asset{
							Name:         name,
							Size:         fileInfo.Size(),
							ModTime:      fileInfo.ModTime(),
							CreationTime: CreationTime(absolutePath, fileInfo),
						})
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
			serveFile(w, r, file, fileInfo, fileType, "no-store")
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
		isS3Storage := false
		if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
			_, isS3Storage = remoteFS.storage.(*S3Storage)
		}
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
			"imgURL": func(asset Asset) template.URL {
				if nbrew.ImgDomain != "" && isS3Storage {
					return template.URL("https://" + nbrew.ImgDomain + "/" + encodeUUID(asset.FileID) + path.Ext(asset.Name))
				}
				return template.URL("/" + path.Join("files", response.SitePrefix, response.AssetDir, asset.Name) + "?raw")
			},
			"isInClipboard": func(name string) bool {
				if sitePrefix != clipboard.Get("sitePrefix") {
					return false
				}
				if response.AssetDir != clipboard.Get("parent") {
					return false
				}
				return isInClipboard[name]
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
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from": "files",
				},
				"templateError": response.TemplateError,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, filePath), http.StatusFound)
		}
		if nbrew.UsersDB != nil {
			// TODO: calculate the available storage space of the owner and add
			// it as a MaxBytesReader to the request body.
			//
			// TODO: but then: how do we differentiate between a MaxBytesError
			// returned by a file exceeding 10 MB vs a MaxBytesError returned
			// by the request body exceeding available storage space? Maybe if
			// maxBytesErr is 10 MB we assume it's a file going over the limit,
			// otherwise we assume it's the owner exceeding his storage space?
		}

		if !isEditable {
			methodNotAllowed(w, r)
			return
		}

		var request struct {
			Content string
		}
		var reader *multipart.Reader
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&request)
			if err != nil {
				badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			err := r.ParseForm()
			if err != nil {
				badRequest(w, r, err)
				return
			}
			request.Content = r.Form.Get("content")
		case "multipart/form-data":
			reader, err = r.MultipartReader()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			for i := 0; i < 2; i++ {
				part, err := reader.NextPart()
				if err != nil {
					if err == io.EOF {
						break
					}
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				formName := part.FormName()
				if formName == "ext" {
					continue
				}
				var maxBytesErr *http.MaxBytesError
				var b strings.Builder
				_, err = io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
				if err != nil {
					if errors.As(err, &maxBytesErr) {
						badRequest(w, r, err)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				if formName == "content" {
					request.Content = b.String()
				}
			}
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
		if fileInfo, ok := fileInfo.(*RemoteFileInfo); ok {
			response.CreationTime = fileInfo.CreationTime
		} else {
			var absolutePath string
			if localFS, ok := nbrew.FS.(*LocalFS); ok {
				absolutePath = path.Join(localFS.rootDir, sitePrefix, response.FilePath)
			}
			response.CreationTime = CreationTime(absolutePath, fileInfo)
		}

		writer, err := nbrew.FS.OpenWriter(path.Join(sitePrefix, filePath), 0644)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		defer writer.Close()
		_, err = io.Copy(writer, strings.NewReader(response.Content))
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

		head, tail, _ := strings.Cut(filePath, "/")
		if (head == "pages" || head == "posts") && contentType == "multipart/form-data" {
			writeFile := func(ctx context.Context, filePath string, reader io.Reader) error {
				writer, err := nbrew.FS.WithContext(ctx).OpenWriter(filePath, 0644)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return err
					}
					err := nbrew.FS.WithContext(r.Context()).MkdirAll(path.Dir(filePath), 0755)
					if err != nil {
						return err
					}
					writer, err = nbrew.FS.WithContext(ctx).OpenWriter(filePath, 0644)
					if err != nil {
						return err
					}
				}
				defer writer.Close()
				_, err = io.Copy(writer, reader)
				if err != nil {
					_ = nbrew.FS.WithContext(ctx).Remove(filePath)
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			}
			var outputDir string
			if head == "posts" {
				outputDir = path.Join(sitePrefix, "output/posts", strings.TrimSuffix(tail, ".md"))
			} else {
				outputDir = path.Join(sitePrefix, "output", strings.TrimSuffix(tail, ".html"))
			}
			tempDir, err := filepath.Abs(filepath.Join(os.TempDir(), "notebrew-temp"))
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			group, groupctx := errgroup.WithContext(r.Context())
			for {
				part, err := reader.NextPart()
				if err != nil {
					if err == io.EOF {
						break
					}
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				formName := part.FormName()
				if formName != "file" {
					continue
				}
				_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
				if err != nil {
					continue
				}
				fileName := params["filename"]
				if strings.Contains(fileName, "/") {
					continue
				}
				fileName = filenameSafe(fileName)
				filePath := path.Join(outputDir, fileName)
				_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), filePath)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
				} else {
					response.FilesExist = append(response.FilesExist, fileName)
					continue
				}
				ext := path.Ext(fileName)
				switch ext {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					cmdPath, err := exec.LookPath("nbrew-process-img")
					if err != nil {
						err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, 10<<20 /* 10 MB */))
						if err != nil {
							var maxBytesErr *http.MaxBytesError
							if errors.As(err, &maxBytesErr) {
								response.FilesTooBig = append(response.FilesTooBig, fileName)
								continue
							}
							getLogger(r.Context()).Error(err.Error())
							internalServerError(w, r, err)
							return
						}
						continue
					}
					id := NewID()
					inputPath := path.Join(tempDir, encodeUUID(id)+"-input"+ext)
					outputPath := path.Join(tempDir, encodeUUID(id)+"-output"+ext)
					input, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
					if err != nil {
						if !errors.Is(err, fs.ErrNotExist) {
							getLogger(r.Context()).Error(err.Error())
							internalServerError(w, r, err)
							return
						}
						err := os.MkdirAll(filepath.Dir(inputPath), 0755)
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
							internalServerError(w, r, err)
							return
						}
						input, err = os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
							internalServerError(w, r, err)
							return
						}
					}
					_, err = io.Copy(input, http.MaxBytesReader(nil, part, 10<<20 /* 10 MB */))
					if err != nil {
						os.Remove(inputPath)
						var maxBytesErr *http.MaxBytesError
						if errors.As(err, &maxBytesErr) {
							response.FilesTooBig = append(response.FilesTooBig, fileName)
							continue
						}
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
					err = input.Close()
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
					group.Go(func() error {
						defer os.Remove(inputPath)
						defer os.Remove(outputPath)
						cmd := exec.CommandContext(groupctx, cmdPath, inputPath, outputPath)
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stderr
						err := cmd.Run()
						if err != nil {
							return err
						}
						output, err := os.Open(outputPath)
						if err != nil {
							return err
						}
						err = writeFile(groupctx, filePath, output)
						if err != nil {
							return err
						}
						return nil
					})
				}
			}
			err = group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}

		switch head {
		case "pages":
			siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			err = siteGen.GeneratePage(r.Context(), filePath, response.Content)
			if err != nil {
				if !errors.As(err, &response.TemplateError) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
		case "posts":
			siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			var templateErrPtr atomic.Pointer[TemplateError]
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				var templateErr TemplateError
				tmpl, err := siteGen.PostTemplate(groupctx)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				err = siteGen.GeneratePost(groupctx, filePath, response.Content, tmpl)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				return nil
			})
			group.Go(func() error {
				var templateErr TemplateError
				category := path.Dir(tail)
				tmpl, err := siteGen.PostListTemplate(groupctx, category)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				_, err = siteGen.GeneratePostList(r.Context(), category, tmpl)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				return nil
			})
			err = group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
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
		// If file is a RemoteFile is gzippable and is not fulltext indexed,
		// its contents are already gzipped. We can reach directly into its
		// buffer and skip the gzipping step.
		if remoteFile.fileType.IsGzippable && !remoteFile.isFulltextIndexed {
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
