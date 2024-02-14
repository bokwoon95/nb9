package nb9

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/nb9/sq"
)

func (nbrew *Notebrew) search(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Match struct {
		FilePath     string    `json:"filePath"`
		Preview      string    `json:"preview"`
		CreationTime time.Time `json:"creationTime"`
	}
	type Request struct {
		Parent string `json:"parent"`
		Text   string `json:"text"`
	}
	type Response struct {
		Error       string     `json:"error,omitempty"`
		ContentSite string     `json:"contentSite,omitempty"`
		Username    NullString `json:"username"`
		SitePrefix  string     `json:"sitePrefix"`
		Parent      string     `json:"parent,omitempty"`
		Text        string     `json:"text,omitempty"`
		Exts        []string   `json:"exts,omitempty"`
		Matches     []Match    `json:"matches,omitempty"`
	}

	isValidParent := func(parent string) bool {
		if !fs.ValidPath(parent) || strings.Contains(parent, "\\") {
			return false
		}
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
		referer := getReferer(r)
		extMap := make(map[string]struct{})
		for _, ext := range response.Exts {
			extMap[ext] = struct{}{}
		}
		funcMap := map[string]any{
			"join":       path.Join,
			"hasPrefix":  strings.HasPrefix,
			"trimPrefix": strings.TrimPrefix,
			"contains":   strings.Contains,
			"stylesCSS":  func() template.CSS { return template.CSS(stylesCSS) },
			"baselineJS": func() template.JS { return template.JS(baselineJS) },
			"referer":    func() string { return referer },
			"hasExt": func(ext string) bool {
				_, ok := extMap[ext]
				return ok
			},
		}
		tmpl, err := template.New("search.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/search.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		executeTemplate(w, r, tmpl, &response)
	}

	var response Response
	response.ContentSite = nbrew.contentSite(sitePrefix)
	response.Username = NullString{String: username, Valid: nbrew.UsersDB != nil}
	response.SitePrefix = sitePrefix
	response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
	response.Text = strings.TrimSpace(r.Form.Get("text"))
	if r.Form.Has("ext") {
		for _, ext := range r.Form["ext"] {
			switch ext {
			case ".html", ".css", ".js", ".md", ".txt":
				response.Exts = append(response.Exts, ext)
			}
		}
	}
	if !isValidParent(response.Parent) {
		response.Parent = "."
	}
	if response.Text == "" {
		writeResponse(w, r, response)
		return
	}
	var err error
	switch remoteFS.filesDialect {
	case "sqlite":
		var parentFilter sq.Expression
		parent := path.Join(sitePrefix, response.Parent)
		if parent == "." {
			parentFilter = sq.Expr("(file_path LIKE 'notes/%'" +
				" OR file_path LIKE 'pages/%'" +
				" OR file_path LIKE 'posts/%'" +
				" OR file_path LIKE 'output/%')")
		} else {
			parentFilter = sq.Expr("file_path LIKE {} ESCAPE '\\'", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(parent)+"/%")
		}
		extensionFilter := sq.Expr("1 = 1")
		if len(response.Exts) > 0 {
			var b strings.Builder
			b.WriteString("(")
			for i, ext := range response.Exts {
				if i > 0 {
					b.WriteString(" OR ")
				}
				b.WriteString("file_path LIKE '%" + ext + "'")
			}
			b.WriteString(")")
			extensionFilter = sq.Expr(b.String())
		}
		response.Matches, err = sq.FetchAll(r.Context(), remoteFS.filesDB, sq.Query{
			Dialect: remoteFS.filesDialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" JOIN files_fts5 ON files_fts5.rowid = files.rowid" +
				" WHERE {parentFilter}" +
				" AND files_fts5.text MATCH {text}" +
				" AND {extensionFilter}" +
				" ORDER BY files_fts5.rank, files.creation_time DESC",
			Values: []any{
				sq.Param("parentFilter", parentFilter),
				sq.StringParam("text", `"`+strings.ReplaceAll(response.Text, `"`, `""`)+`"`),
				sq.Param("extensionFilter", extensionFilter),
			},
		}, func(row *sq.Row) Match {
			match := Match{
				FilePath:     row.String("files.file_path"),
				Preview:      row.String("substr(files.text, 1, 500)"),
				CreationTime: row.Time("files.creation_time"),
			}
			if sitePrefix != "" {
				_, match.FilePath, _ = strings.Cut(match.FilePath, "/")
			}
			return match
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
	case "postgres":
	case "mysql":
	}
	writeResponse(w, r, response)
}
