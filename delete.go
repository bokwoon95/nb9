package nb9

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

func (nbrew *Notebrew) delet(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Request struct {
		Parent string   `json:"parent,omitempty"`
		Names  []string `json:"names,omitempty"`
	}
	type File struct {
		Name    string    `json:"name,omitempty"`
		IsDir   bool      `json:"isDir,omitempty"`
		Size    int64     `json:"size,omitempty"`
		ModTime time.Time `json:"modTime,omitempty"`
	}
	type Response struct {
		Error       string     `json:"status"`
		Errors      []string   `json:"errors,omitempty"`
		ContentSite string     `json:"contentSite,omitempty"`
		Username    NullString `json:"username"`
		SitePrefix  string     `json:"sitePrefix"`
		Parent      string     `json:"parent,omitempty"`
		Files       []File     `json:"files,omitempty"`
	}

	isValidParent := func(parent string) bool {
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

	switch r.Method {
	case "GET":
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
			funcMap := map[string]any{
				"join":       path.Join,
				"base":       path.Base,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"stylesCSS":  func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS": func() template.JS { return template.JS(baselineJS) },
				"referer":    func() string { return referer },
				"head": func(s string) string {
					head, _, _ := strings.Cut(s, "/")
					return head
				},
				"tail": func(s string) string {
					_, tail, _ := strings.Cut(s, "/")
					return tail
				},
			}
			tmpl, err := template.New("delete.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/delete.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
			executeTemplate(w, r, tmpl, &response)
		}

		var response Response
		_, err := nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentSite = nbrew.contentSite(sitePrefix)
		response.Username = NullString{String: username, Valid: nbrew.UsersDB != nil}
		response.SitePrefix = sitePrefix
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		if !isValidParent(response.Parent) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		// TODO: list all deletable files efficiently (if remoteFS, use a prepared statement on a transaction).
		writeResponse(w, r, response)
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
			if response.Error != "" {
				err := nbrew.setSession(w, r, "flash", &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "createfile")+"/?parent="+url.QueryEscape(response.Parent), http.StatusFound)
				return
			}
			var b strings.Builder
			if len(response.Files) == 1 {
				b.WriteString("1 file deleted")
			} else {
				b.WriteString(strconv.Itoa(len(response.Files)) + " files deleted")
			}
			if len(response.Errors) == 1 {
				b.WriteString(" (1 error)")
			} else {
				b.WriteString(" ("+strconv.Itoa(len(response.Errors)) + " errors)")
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]string{
					"from": "delete",
					"msg":  b.String(),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
		}

		var request Request
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
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
				err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
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
			request.Parent = r.Form.Get("parent")
			request.Names = r.Form["name"]
		default:
			unsupportedContentType(w, r)
			return
		}

		var response Response
		response.Parent = path.Clean(strings.Trim(request.Parent, "/"))
		if !isValidParent(response.Parent) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		// TODO: delete all files efficiently (if remoteFS, use a prepared statement on a transaction).
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
