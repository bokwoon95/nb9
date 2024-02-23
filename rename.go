package nb9

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func (nbrew *Notebrew) rename(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Request struct {
		Parent  string `json:"parent"`
		OldName string `json:"oldName"`
		NewName string `json:"newName"`
	}
	type Response struct {
		Error       string     `json:"status"`
		FormErrors  url.Values `json:"formErrors,omitempty"`
		ContentSite string     `json:"contentSite,omitempty"`
		Username    NullString `json:"username"`
		SitePrefix  string     `json:"sitePrefix"`
		Parent      string     `json:"parent"`
		OldName     string     `json:"oldName"`
		NewName     string     `json:"newName"`
		IsDir       bool       `json:"isDir"`
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
			}
			tmpl, err := template.New("rename.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/rename.html")
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
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes", "pages", "posts", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, response.OldName))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					response.Error = "InvalidFile"
					writeResponse(w, r, response)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			response.IsDir = fileInfo.IsDir()
		default:
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		response.OldName = r.Form.Get("oldName")
		response.NewName = r.Form.Get("newName")
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
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "createfolder")+"/?parent="+url.QueryEscape(response.Parent)+"&oldName="+url.QueryEscape(response.OldName), http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":    "rename",
					"parent":  response.Parent,
					"oldName": response.OldName,
					"newName": response.NewName,
					"isDir":   response.IsDir,
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
			request.OldName = r.Form.Get("oldName")
			request.NewName = r.Form.Get("newName")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			FormErrors: make(url.Values),
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			OldName:    request.OldName,
			NewName:    request.NewName,
		}
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			if filenameSafe(response.NewName) != response.NewName {
				response.FormErrors.Add("newName", "") // shit we can't just normalize silently, we need to report back to the user why their name is not allowed. Which means we can't use filenameSafe, we need to use the underlying isFilenameUnsafe character slice.
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, response.OldName))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					response.Error = "InvalidFile"
					writeResponse(w, r, response)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			response.IsDir = fileInfo.IsDir()
		case "pages", "posts", "output":
			if urlSafe(response.NewName) != response.NewName {
				response.FormErrors.Add("newName", "") // shit we can't just normalize silently, we need to report back to the user why their name is not allowed. Which means we can't use urlSafe, we need to use the underlying isURLUnsafe character slice.
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, response.OldName))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					response.Error = "InvalidFile"
					writeResponse(w, r, response)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			response.IsDir = fileInfo.IsDir()
		default:
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		// TODO: take newName at face value.
	default:
		methodNotAllowed(w, r)
	}
}
