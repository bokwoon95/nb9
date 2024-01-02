package nb9

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

type fileEntry struct {
	Name    string    `json:"name,omitempty"`
	Size    int64     `json:"size,omitempty"`
	ModTime time.Time `json:"modTime,omitempty"`
	IsDir   bool      `json:"isDir,omitempty"`
}

type fileResponse struct {
	Status      Status    `json:"status"`
	ContentSite string    `json:"contentSite,omitempty"`
	Username    string    `json:"username,omitempty"`
	SitePrefix  string    `json:"sitePrefix,omitempty"`
	Path        string    `json:"path"`
	IsDir       bool      `json:"isDir,omitempty"`
	ModTime     time.Time `json:"modTime,omitempty"`

	Files []fileEntry `json:"fileEntries,omitempty"`
	Sites []string    `json:"sites,omitempty"`
	Users []string    `json:"users,omitempty"`

	URL            string      `json:"url,omitempty"`
	BelongsTo      string      `json:"belongsTo,omitempty"`
	AssetDir       string      `json:"assetDir,omitempty"`
	Assets         []fileEntry `json:"assetEntries,omitempty"`
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

	// TODO: is the file editable? isEditable
	// TODO: does the file have an output/parent link? URL/BelongsTo
	// TODO: $.ContentSite
	// back | files | <type> | <parent> | <view URL, belongs to page>

	switch r.Method {
	case "GET":
		var response fileResponse
		_, err = nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		if response.Status == "" {
			response.Status = GetSuccess // TODO: do it like this? set status here?
		}
		response.ContentSite = nbrew.contentSite(sitePrefix)
		response.Username = username
		response.SitePrefix = sitePrefix
		response.Path = filePath
		response.IsDir = fileInfo.IsDir()
		response.ModTime = fileInfo.ModTime()
		switch head {
		case "pages":
			if tail == "index.html" {
				response.AssetDir = "output"
				response.URL = response.ContentSite
			} else {
				response.AssetDir = path.Join("output", strings.TrimSuffix(tail, ".html"))
				response.URL = response.ContentSite + "/" + strings.TrimSuffix(tail, ".html") + "/"
			}
			// TODO: based on RemoteFS or not, fill in the Assets
		case "posts":
			response.AssetDir = path.Join("output", strings.TrimSuffix(filePath, ".md"))
			response.URL = response.ContentSite + "/" + strings.TrimSuffix(filePath, ".md") + "/"
			// TODO: based on RemoteFS or not, fill in the Assets
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
				"contains":         strings.Contains,
				"fileSizeToString": fileSizeToString,
				"stylesCSS":        func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS":       func() template.JS { return template.JS(baselineJS) },
				// "contentURL":       func() string { return contentURL },
				"hasDatabase": func() bool { return nbrew.UsersDB != nil },
				"referer":     func() string { return referer },
				"safeHTML":    func(s string) template.HTML { return template.HTML(s) },
				// "pagePath":         func() string { return pagePath },
				// "pageURL":          func() string { return pageURL },
				// "postURL":          func() string { return postURL },
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
			return
		}
		// TODO: if we reach here, it means the file is not editable and we serve the file directly. If not a RemoteFile, we can just reuse serveFile. Otherwise, we do custom logic to serve the RemoteFile that we already have.
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
