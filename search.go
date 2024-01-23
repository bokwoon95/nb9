package nb9

import "net/http"

func (nbrew *Notebrew) search(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Request struct {
		Parent string `json:"parent,omitempty"`
		Search string `json:"search,omitempty"`
	}
	type Match struct {
		LineNumber int        `json:"lineNumber"`
		Lines      [][]string `json:"lines,omitempty"`
	}
	type File struct {
		FilePath string  `json:"filePath"`
		Matches  []Match `json:"matches,omitempty"`
	}
	type Response struct {
		ContentSite string     `json:"contentSite,omitempty"`
		Username    NullString `json:"username"`
		SitePrefix  string     `json:"sitePrefix"`
		Parent      string     `json:"parent,omitempty"`
		Search      string     `json:"search,omitempty"`
		Files       []File     `json:"files,omitempty"`
	}
}
