package nb9

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func (nbrew *Notebrew) createfile(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Request struct {
		Parent string `json:"parent,omitempty"`
		Name   string `json:"name,omitempty"`
	}
	type Response struct {
		Error       string     `json:"error,omitempty"`
		FormErrors  url.Values `json:"formErrors,omitempty"`
		ContentSite string     `json:"contentSite"`
		Username    NullString `json:"username"`
		SitePrefix  string     `json:"sitePrefix"`
		Parent      string     `json:"parent,omitempty"`
		Name        string     `json:"name,omitempty"`
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
			tmpl, err := template.New("createfile.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/createfile.html")
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
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]string{
					"from": "createfile",
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent, response.Name), http.StatusFound)
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
			request.Name = r.Form.Get("name")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			FormErrors: make(url.Values),
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			Name:       urlSafe(request.Name),
		}
		if !isValidParent(response.Parent) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		if response.Name == "" {
			response.FormErrors.Add("name", "required")
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			switch path.Ext(response.Name) {
			case ".html", ".css", ".js", ".md", ".txt":
				break
			case "":
				response.Name += ".txt"
			default:
				response.FormErrors.Add("name", "invalid extension (must be either .html, .css, .js, .md, .txt or omitted)")
			}
		case "pages":
			switch path.Ext(response.Name) {
			case ".html":
				break
			case "":
				response.Name += ".html"
			default:
				response.FormErrors.Add("name", "extension must be .html or omitted")
			}
		case "posts":
			switch path.Ext(response.Name) {
			case ".md":
				break
			case "":
				response.Name += ".md"
			default:
				response.FormErrors.Add("name", "extension must be .md or omitted")
			}
		default:
			switch path.Ext(response.Name) {
			case ".html", ".css", ".js", ".md", ".txt":
				break
			case "":
				response.FormErrors.Add("name", "missing extension (must be either .html, .css, .js, .md or .txt)")
			default:
				response.FormErrors.Add("name", "invalid extension (must be either .html, .css, .js, .md or .txt)")
			}
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		writer, err := nbrew.FS.OpenWriter(path.Join(sitePrefix, response.Parent, response.Name), 0644)
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
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
