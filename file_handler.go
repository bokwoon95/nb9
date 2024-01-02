package nb9

import (
	"errors"
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
	if !strings.Contains(filePath, "/") {
		notFound(w, r)
		return
	}

	var response fileResponse
	if r.Method == "GET" {
		_, err = nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		if response.Status == "" {
			response.Status = GetSuccess // TODO: do it like this? set status here?
		}
	}
	response.ContentSite = nbrew.contentSite(sitePrefix)
	response.Username = username
	response.SitePrefix = sitePrefix
	response.Path = filePath
	response.IsDir = fileInfo.IsDir()
	response.ModTime = fileInfo.ModTime()

	var isEditable bool
	head, tail, _ := strings.Cut(filePath, "/")
	switch head {
	case "notes":
		isEditable = fileType.Ext == ".html" || fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md" || fileType.Ext == ".txt"
	case "pages":
		isEditable = fileType.Ext == ".html"
		if !isEditable {
			notFound(w, r)
			return
		}
		if tail == "index.html" {
			response.AssetDir = "output"
			response.URL = response.ContentSite
		} else {
			response.AssetDir = path.Join("output", strings.TrimSuffix(tail, ".html"))
			response.URL = response.ContentSite + "/" + strings.TrimSuffix(tail, ".html") + "/"
		}
	case "posts":
		isEditable = fileType.Ext == ".md"
		if !isEditable {
			notFound(w, r)
			return
		}
	case "output":
		next, _, _ := strings.Cut(tail, "/")
		switch next {
		case "posts":
			isEditable = false
		case "themes":
			isEditable = fileType.Ext == ".html" || fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md" || fileType.Ext == ".txt"
		default:
			isEditable = fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md"
			if isEditable {
				// output/foo/bar/baz.js => pages/foo/bar.html
				response.BelongsTo = path.Dir(tail) + ".html"
			}
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
	case "POST":
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
