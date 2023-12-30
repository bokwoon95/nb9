package nb9

import (
	"net/http"
	"time"
)

type fileEntry struct {
	Name    string    `json:"name,omitempty"`
	IsDir   bool      `json:"isDir,omitempty"`
	IsSite  bool      `json:"isSite,omitempty"`
	IsUser  bool      `json:"isUser,omitempty"`
	Size    int64     `json:"size,omitempty"`
	ModTime time.Time `json:"modTime,omitempty"`
}

type fileResponse struct {
	Status         Status      `json:"status"`
	ContentDomain  string      `json:"contentDomain,omitempty"`
	Username       string      `json:"username,omitempty"`
	SitePrefix     string      `json:"sitePrefix,omitempty"`
	Path           string      `json:"path"`
	IsDir          bool        `json:"isDir,omitempty"`
	ModTime        time.Time   `json:"modTime,omitempty"`
	FileEntries    []fileEntry `json:"fileEntries,omitempty"`
	TemplateErrors []string    `json:"templateErrors,omitempty"`
}

func (nbrew *Notebrew) fileHandler(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string) {
	// TODO: assume is a file first
}

func (nbrew *Notebrew) listDirectory() {
}

// displayFile
// updateFile
// listDir
