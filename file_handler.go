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

	IsDir  bool `json:"isDir,omitempty"`
	IsSite bool `json:"isSite,omitempty"`
	IsUser bool `json:"isUser,omitempty"`
}

type fileResponse struct {
	Status      Status      `json:"status"`
	ContentSite string      `json:"contentSite,omitempty"`
	Username    string      `json:"username,omitempty"`
	SitePrefix  string      `json:"sitePrefix,omitempty"`
	Path        string      `json:"path"`
	IsDir       bool        `json:"isDir,omitempty"`
	ModTime     time.Time   `json:"modTime,omitempty"`
	FileEntries []fileEntry `json:"fileEntries,omitempty"`

	URL            string   `json:"url,omitempty"`
	BelongsTo      string   `json:"belongsTo,omitempty"`
	TemplateErrors []string `json:"templateErrors,omitempty"`
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
	_ = fileType
	// TODO: is the file editable? isEditable
	// TODO: does the file have an output/parent link? URL/BelongsTo
	// TODO: $.ContentSite
	// back | files | <type> | <parent> | <view URL, belongs to page>
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
