package nb9

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
)

func (nbrew *Notebrew) file(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string, fileInfo fs.FileInfo) {
	type FileEntry struct {
		Name        string    `json:"name,omitempty"`
		ContentType string    `json:"contentType,omitempty"`
		Size        int64     `json:"size,omitempty"`
		ModTime     time.Time `json:"modTime,omitempty"`
	}
	type Response struct {
		Status         Error       `json:"status"`
		ContentDomain  string      `json:"contentDomain,omitempty"`
		Username       string      `json:"username,omitempty"`
		SitePrefix     string      `json:"sitePrefix,omitempty"`
		Path           string      `json:"path"`
		IsDir          bool        `json:"isDir,omitempty"`
		ModTime        time.Time   `json:"modTime,omitempty"`
		Size           int64       `json:"size,omitempty"`
		Content        string      `json:"content,omitempty"`
		ContentType    string      `json:"contentType,omitempty"`
		AssetDir       string      `json:"assetDir,omitempty"`
		AssetEntries   []FileEntry `json:"assetEntries,omitempty"`
		TemplateErrors []string    `json:"templateErrors,omitempty"`
	}
	fileType, ok := fileTypes[path.Ext(filePath)]
	if !ok {
		notFound(w, r)
		return
	}
	segments := strings.Split(filePath, "/")
	if len(segments) <= 1 {
		notFound(w, r)
		return
	}

	// If the current file is a CSS or JS asset for a page, pagePath is the
	// path to that page.
	var pagePath string
	// isEditableText is true if the current file is a text file that can be
	// edited by the user.
	var isEditableText bool
	switch segments[0] {
	case "notes":
		isEditableText = fileType.Ext == ".html" || fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md" || fileType.Ext == ".txt"
	case "pages":
		if fileType.Ext != ".html" {
			notFound(w, r)
			return
		}
		isEditableText = true
	case "posts":
		if fileType.Ext != ".md" {
			notFound(w, r)
			return
		}
		isEditableText = true
	case "output":
		switch segments[1] {
		case "posts":
			isEditableText = false
		case "themes":
			isEditableText = fileType.Ext == ".html" || fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md" || fileType.Ext == ".txt"
		default:
			if fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md" {
				isEditableText = true
				// output/foo/bar/baz.js => pages/foo/bar.html
				segmentsCopy := slices.Clone(segments[:len(segments)-1])
				segmentsCopy[0] = "pages"
				last := len(segmentsCopy) - 1
				segmentsCopy[last] += ".html"
				pagePath = path.Join(segmentsCopy...)
			}
		}
	default:
		notFound(w, r)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1MB */)
	switch r.Method {
	case "GET":
		err := r.ParseForm()
		if err != nil {
			badRequest(w, r, err)
			return
		}

		var response Response
		_, err = nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentDomain = nbrew.ContentDomain
		response.Username = username
		response.SitePrefix = sitePrefix
		response.Path = filePath
		response.IsDir = fileInfo.IsDir()
		response.ModTime = fileInfo.ModTime()
		response.Size = fileInfo.Size()
		response.ContentType = fileType.ContentType
		response.Status = Success
		if isEditableText {
			file, err := nbrew.FS.Open(path.Join(sitePrefix, filePath))
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
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
		var pageURL, postURL string
		contentURL := nbrew.contentURL(sitePrefix)
		switch segments[0] {
		case "pages":
			if len(segments) == 2 && segments[1] == "index.html" {
				// (page) pages/index.html => (assetDir) output
				response.AssetDir = "output"
				pageURL = contentURL
			} else {
				// (page) pages/foo.html     => (assetDir) output/foo
				// (page) pages/foo/bar.html => (assetDir) output/foo/bar
				newSegments := slices.Clone(segments)
				newSegments[0] = "output"
				last := len(newSegments) - 1
				newSegments[last] = strings.TrimSuffix(newSegments[last], ".html")
				response.AssetDir = path.Join(newSegments...)
				pageURL = contentURL + "/" + strings.TrimPrefix(response.AssetDir, "output/") + "/"
			}
			dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, response.AssetDir))
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				err = nbrew.FS.MkdirAll(path.Join(sitePrefix, response.AssetDir), 0755)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				dirEntries, err = nbrew.FS.ReadDir(path.Join(sitePrefix, response.AssetDir))
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
			for _, dirEntry := range dirEntries {
				if dirEntry.IsDir() {
					continue
				}
				name := dirEntry.Name()
				fileType, ok := fileTypes[path.Ext(name)]
				if !ok {
					continue
				}
				if fileType.Ext != ".css" && fileType.Ext != ".js" && fileType.Ext != ".md" && !strings.HasPrefix(fileType.ContentType, "image") {
					continue
				}
				fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.AssetDir, name))
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				response.AssetEntries = append(response.AssetEntries, FileEntry{
					Name:        name,
					Size:        fileInfo.Size(),
					ModTime:     fileInfo.ModTime(),
					ContentType: fileType.ContentType,
				})
			}
		case "posts":
			// (post) posts/foo/bar.md => (assetDir) output/posts/foo/bar
			newSegments := slices.Clone(segments)
			newSegments[0] = "output/posts"
			last := len(newSegments) - 1
			newSegments[last] = strings.TrimSuffix(newSegments[last], ".md")
			response.AssetDir = path.Join(newSegments...)
			postURL = contentURL + "/" + strings.TrimPrefix(response.AssetDir, "output/") + "/"
			dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, response.AssetDir))
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				err = nbrew.FS.MkdirAll(path.Join(sitePrefix, response.AssetDir), 0755)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				dirEntries, err = nbrew.FS.ReadDir(path.Join(sitePrefix, response.AssetDir))
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
			for _, dirEntry := range dirEntries {
				if dirEntry.IsDir() {
					continue
				}
				name := dirEntry.Name()
				fileType, ok := fileTypes[path.Ext(name)]
				if !ok {
					continue
				}
				if !strings.HasPrefix(fileType.ContentType, "image") {
					continue
				}
				fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.AssetDir, name))
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				response.AssetEntries = append(response.AssetEntries, FileEntry{
					Name:    name,
					Size:    fileInfo.Size(),
					ModTime: fileInfo.ModTime(),
				})
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

		if !isEditableText {
			serveFile(w, r, nbrew.FS, path.Join(sitePrefix, filePath))
			return
		}

		funcMap := map[string]any{
			"join":             path.Join,
			"dir":              path.Dir,
			"base":             path.Base,
			"ext":              path.Ext,
			"hasPrefix":        strings.HasPrefix,
			"trimPrefix":       strings.TrimPrefix,
			"contains":         strings.Contains,
			"fileSizeToString": fileSizeToString,
			"stylesCSS":        func() template.CSS { return template.CSS(stylesCSS) },
			"baselineJS":       func() template.JS { return template.JS(baselineJS) },
			"contentURL":       func() string { return contentURL },
			"hasDatabase":      func() bool { return nbrew.DB != nil },
			"referer":          func() string { return r.Referer() },
			"safeHTML":         func(s string) template.HTML { return template.HTML(s) },
			"pagePath":         func() string { return pagePath },
			"pageURL":          func() string { return pageURL },
			"postURL":          func() string { return postURL },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
		}
		tmpl, err := template.New("file.html").Funcs(funcMap).ParseFS(rootFS, "embed/file.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		executeTemplate(w, r, fileInfo.ModTime(), tmpl, &response)
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
			err := nbrew.setSession(w, r, "flash", &response)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, filePath), http.StatusFound)
		}

		if !isEditableText {
			methodNotAllowed(w, r)
			return
		}

		var request struct {
			Content string `json:"content"`
		}
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(15 << 20 /* 15MB */)
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
			request.Content = r.Form.Get("content")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			Path:    filePath,
			IsDir:   fileInfo.IsDir(),
			ModTime: fileInfo.ModTime(),
			Content: request.Content,
		}

		if nbrew.DB != nil {
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

		head, tail, _ := strings.Cut(filePath, "/")
		switch head {
		case "pages":
			siteGen, err := NewSiteGenerator(SiteGeneratorConfig{
				ContentDomain:        nbrew.ContentDomain,
				FS:                   nbrew.FS,
				SitePrefix:           sitePrefix,
				GzipGeneratedContent: nbrew.GzipGeneratedContent.Load(),
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			err = siteGen.GeneratePage(r.Context(), tail)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		case "posts":
			siteGen, err := NewSiteGenerator(SiteGeneratorConfig{
				ContentDomain:        nbrew.ContentDomain,
				FS:                   nbrew.FS,
				SitePrefix:           sitePrefix,
				GzipGeneratedContent: nbrew.GzipGeneratedContent.Load(),
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			err = siteGen.GeneratePost(r.Context(), tail)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		response.Status = UpdateSuccess
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}

func serveFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	if r.Method != "GET" {
		methodNotAllowed(w, r)
		return
	}

	var fileType FileType
	ext := path.Ext(name)
	if ext == ".webmanifest" {
		fileType.Ext = ".webmanifest"
		fileType.ContentType = "application/manifest+json"
		fileType.IsGzippable = true
	} else {
		fileType = fileTypes[ext]
		if fileType.Ext == ".html" {
			// Serve HTML as plaintext so that the browser doesn't display it
			// as markup.
			fileType.ContentType = "text/plain; charset=utf-8"
		}
		if fileType == (FileType{}) {
			notFound(w, r)
			return
		}
	}

	file, err := fsys.Open(name)
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
		notFound(w, r)
		return
	}

	// TODO: we can skip buffering the bytes if it's an *os.File which can be
	// rewinded. And if it's a *RemoteFile of type text, we already have the
	// bytes in memory and can hash that directly.
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	hasher := hashPool.Get().(hash.Hash)
	hasher.Reset()
	defer hashPool.Put(hasher)

	multiWriter := io.MultiWriter(buf, hasher)
	if !fileType.IsGzippable {
		_, err = io.Copy(multiWriter, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
	} else {
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
	}

	b := bytesPool.Get().(*[]byte)
	*b = (*b)[:0]
	defer bytesPool.Put(b)

	if _, ok := w.Header()["Content-Type"]; !ok {
		w.Header().Set("Content-Type", fileType.ContentType)
	}
	if fileType.IsGzippable {
		w.Header().Set("Content-Encoding", "gzip")
	}
	w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(*b))+`"`)
	http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
}
