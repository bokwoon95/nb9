package nb9

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

func (nbrew *Notebrew) createfile(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Request struct {
		Parent  string
		Name    string
		Ext     string
		Content string
	}
	type Response struct {
		Error          string     `json:"error,omitempty"`
		FormErrors     url.Values `json:"formErrors,omitempty"`
		TemplateErrors []string   `json:"templateErrors,omitempty"`
		ContentSite    string     `json:"contentSite"`
		Username       NullString `json:"username"`
		SitePrefix     string     `json:"sitePrefix"`
		Parent         string     `json:"parent,omitempty"`
		Name           string     `json:"name,omitempty"`
		Ext            string     `json:"ext,omitempty"`
		Content        string     `json:"content,omitempty"`
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
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			response.Ext = ".txt"
		case "pages":
			response.Ext = ".html"
		case "posts":
			response.Ext = ".md"
		default:
			response.Ext = ".html"
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
				"postRedirectGet": map[string]any{
					"from": "createfile",
				},
				"templateErrors": response.TemplateErrors,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent, response.Name+response.Ext), http.StatusFound)
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
			request.Ext = r.Form.Get("ext")
			request.Content = r.Form.Get("content")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			FormErrors: make(url.Values),
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			Name:       urlSafe(request.Name),
			Ext:        request.Ext,
			Content:    request.Content,
		}
		if !isValidParent(response.Parent) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			if response.Ext != ".html" && response.Ext != ".css" && response.Ext != ".js" && response.Ext != ".md" && response.Ext != ".txt" {
				response.Ext = ".txt"
			}
		case "pages":
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			if response.Ext != ".html" {
				response.Ext = ".html"
			}
			if response.Parent != "" && response.Name == "index" && response.Ext == ".html" {
				response.FormErrors.Add("name", "this name is not allowed")
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		case "posts":
			var timestamp [8]byte
			binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
			prefix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			if response.Name == "" {
				response.Name = prefix
			} else {
				response.Name = prefix + "-" + response.Name
			}
			if response.Ext != ".md" {
				response.Ext = ".md"
			}
		default:
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			if response.Ext != ".html" && response.Ext != ".css" && response.Ext != ".js" && response.Ext != ".md" && response.Ext != ".txt" {
				response.Ext = ".html"
			}
		}
		_, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, response.Parent, response.Name))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		} else {
			switch head {
			case "pages":
				response.FormErrors.Add("name", "page already exists")
			case "posts":
				response.FormErrors.Add("name", "post already exists")
			default:
				response.FormErrors.Add("name", "file already exists")
			}
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		writer, err := nbrew.FS.WithContext(r.Context()).OpenWriter(path.Join(sitePrefix, response.Parent, response.Name+response.Ext), 0644)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		defer writer.Close()
		_, err = io.WriteString(writer, response.Content)
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
		if head == "pages" || head == "posts" {
			siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.CDNDomain)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			switch head {
			case "pages":
				err := siteGen.GeneratePage(r.Context(), path.Join(response.Parent, response.Name+response.Ext), response.Content)
				if err != nil {
					var parseErr TemplateParseError
					var executionErr *TemplateExecutionError
					if errors.As(err, &parseErr) {
						response.TemplateErrors = append(response.TemplateErrors, parseErr.List()...)
					} else if errors.As(err, &executionErr) {
						response.TemplateErrors = append(response.TemplateErrors, executionErr.Err.Error())
					} else {
						getLogger(r.Context()).Error(err.Error())
					}
				}
			case "posts":
				tmpl, err := siteGen.PostTemplate(r.Context())
				if err != nil {
					var parseErr TemplateParseError
					var executionErr *TemplateExecutionError
					if errors.As(err, &parseErr) {
						response.TemplateErrors = append(response.TemplateErrors, parseErr.List()...)
					} else if errors.As(err, &executionErr) {
						response.TemplateErrors = append(response.TemplateErrors, executionErr.Err.Error())
					} else {
						getLogger(r.Context()).Error(err.Error())
					}
				} else {
					err := siteGen.GeneratePost(r.Context(), path.Join(response.Parent, response.Name+response.Ext), response.Content, tmpl)
					if err != nil {
						var parseErr TemplateParseError
						var executionErr *TemplateExecutionError
						if errors.As(err, &parseErr) {
							response.TemplateErrors = append(response.TemplateErrors, parseErr.List()...)
						} else if errors.As(err, &executionErr) {
							response.TemplateErrors = append(response.TemplateErrors, executionErr.Err.Error())
						} else {
							getLogger(r.Context()).Error(err.Error())
						}
					} else {
						category := tail
						tmpl, err := siteGen.PostListTemplate(r.Context(), category)
						if err != nil {
							var parseErr TemplateParseError
							var executionErr *TemplateExecutionError
							if errors.As(err, &parseErr) {
								response.TemplateErrors = append(response.TemplateErrors, parseErr.List()...)
							} else if errors.As(err, &executionErr) {
								response.TemplateErrors = append(response.TemplateErrors, executionErr.Err.Error())
							} else {
								getLogger(r.Context()).Error(err.Error())
							}
						} else {
							_, err := siteGen.GeneratePostList(r.Context(), category, tmpl)
							if err != nil {
								var parseErr TemplateParseError
								var executionErr *TemplateExecutionError
								if errors.As(err, &parseErr) {
									response.TemplateErrors = append(response.TemplateErrors, parseErr.List()...)
								} else if errors.As(err, &executionErr) {
									response.TemplateErrors = append(response.TemplateErrors, executionErr.Err.Error())
								} else {
									getLogger(r.Context()).Error(err.Error())
								}
							}
						}
					}
				}
			}
		}
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
