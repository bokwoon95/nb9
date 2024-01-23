package nb9

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/bokwoon95/nb9/sq"
)

func (nbrew *Notebrew) search(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type File struct {
		FilePath string `json:"filePath"`
		Preview  string `json:"preview"`
	}
	type Response struct {
		Error       string     `json:"error,omitempty"`
		ContentSite string     `json:"contentSite,omitempty"`
		Username    NullString `json:"username"`
		SitePrefix  string     `json:"sitePrefix"`
		Parent      string     `json:"parent,omitempty"`
		Search      string     `json:"search,omitempty"`
		Files       []File     `json:"files,omitempty"`
	}

	isValidParent := func(parent string) bool {
		if parent == "." {
			return true
		}
		head, tail, _ := strings.Cut(parent, "/")
		switch head {
		case "notes", "pages", "posts":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, parent))
			if err != nil {
				return false
			}
			if fileInfo.IsDir() {
				return true
			}
		case "output":
			next, _, _ := strings.Cut(tail, "/")
			if next != "themes" {
				return false
			}
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, parent))
			if err != nil {
				return false
			}
			if fileInfo.IsDir() {
				return true
			}
		}
		return false
	}

	if r.Method != "GET" {
		methodNotAllowed(w, r)
		return
	}

	remoteFS, ok := nbrew.FS.(*RemoteFS)
	if !ok {
		notFound(w, r)
		return
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
		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(&response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
	}

	var response Response
	response.ContentSite = nbrew.contentSite(sitePrefix)
	response.Username = NullString{String: username, Valid: nbrew.UsersDB != nil}
	response.SitePrefix = sitePrefix
	response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
	response.Search = strings.TrimSpace(r.Form.Get("search"))
	if !isValidParent(response.Parent) {
		response.Error = "InvalidParent"
		writeResponse(w, r, response)
		return
	}
	if response.Search == "" {
		writeResponse(w, r, response)
		return
	}
	var err error
	switch remoteFS.filesDialect {
	case "sqlite":
		var siteFilter sq.Expression
		if sitePrefix != "" {
			siteFilter = sq.Expr("(file_path LIKE {} ESCAPE '\\')", sitePrefix+"/%")
		} else {
			siteFilter = sq.Expr("(file_path LIKE 'notes/%'" +
				" OR file_path LIKE 'pages/%'" +
				" OR file_path LIKE 'posts/%'" +
				" OR file_path LIKE 'output/%')")
		}
		response.Files, err = sq.FetchAll(r.Context(), remoteFS.filesDB, sq.Query{
			Dialect: remoteFS.filesDialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" JOIN files_fts5 ON files_fts5.rowid = files.rowid" +
				" WHERE {siteFilter}" +
				" AND files_fts5.text MATCH {searchTerm}" +
				" ORDER BY files_fts5.rank",
			Values: []any{
				sq.Param("siteFilter", siteFilter),
				sq.StringParam("searchTerm", `"`+strings.ReplaceAll(response.Search, `"`, `""`)+`"`),
			},
		}, func(row *sq.Row) File {
			return File{
				FilePath: row.String("files.file_path"),
				Preview:  row.String("substr(files.text, 1, 500)"),
			}
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
	}
	writeResponse(w, r, response)
}
