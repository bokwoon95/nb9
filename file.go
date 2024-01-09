package nb9

import (
	"encoding/json"
	"errors"
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
		Name        string
		ContentType string
		Size        int64
		ModTime     time.Time
	}
	type Response struct {
		Status         string
		ContentDomain  string
		Username       string
		SitePrefix     string
		Path           string
		IsDir          bool
		ModTime        time.Time
		Size           int64
		Content        string
		ContentType    string
		AssetDir       string
		AssetEntries   []FileEntry
		TemplateErrors []string
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
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
		if response.Status == "" {
			response.Status = "GetSuccess"
		}
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
		contentURL := nbrew.contentSite(sitePrefix)
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
			fileType := fileTypes[path.Ext(filePath)]
			if fileType.Ext == ".html" {
				fileType.ContentType = "text/plain; charset=utf-8"
			}
			file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, filePath))
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
			serveFile(w, r, file, fileInfo, fileType, "no-cache, must-revalidate")
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
			"contains":         strings.Contains,
			"fileSizeToString": fileSizeToString,
			"stylesCSS":        func() template.CSS { return template.CSS(stylesCSS) },
			"baselineJS":       func() template.JS { return template.JS(baselineJS) },
			"contentURL":       func() string { return contentURL },
			"hasDatabase":      func() bool { return nbrew.UsersDB != nil },
			"referer":          func() string { return referer },
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
		tmpl, err := template.New("file.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/file.html")
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
			Content string
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
				err := r.ParseMultipartForm(15 << 20 /* 15 MB */)
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

		if nbrew.UsersDB != nil {
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
			Title:      "",
			Favicon:    "",
			Lang:       "",
			Categories: nil,
			CodeStyle:  "onedark",
		}
		head, _, _ := strings.Cut(filePath, "/")
		switch head {
		case "pages":
			err := nbrew.generatePage(r.Context(), site, sitePrefix, filePath, response.Content)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		case "posts":
			err := nbrew.generatePost(r.Context(), site, sitePrefix, filePath, response.Content)
			if err != nil {
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
