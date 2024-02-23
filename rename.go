package nb9

import (
	"encoding/json"
	"errors"
	"fmt"
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
		Parent   string `json:"parent"`
		Name     string `json:"name"`
		ChangeTo string `json:"changeTo"`
	}
	type Response struct {
		Error       string     `json:"status"`
		FormErrors  url.Values `json:"formErrors,omitempty"`
		ContentSite string     `json:"contentSite,omitempty"`
		Username    NullString `json:"username"`
		SitePrefix  string     `json:"sitePrefix"`
		Parent      string     `json:"parent"`
		Prefix      string     `json:"prefix"`
		From        string     `json:"from"`
		To          string     `json:"to"`
		Ext         string     `json:"ext"`
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
		name := r.Form.Get("name")
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes", "pages", "posts", "output":
			switch path.Join(response.Parent, response.Name) {
			case "pages/index.html", "pages/404.html", "output/themes/post.html", "output/themes/postlist.html":
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, response.Name))
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
		if response.IsDir && response.Ext == "" {
			response.Error = "InvalidFile"
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
				redirectURL := "/" + path.Join("files", sitePrefix, "rename") + "/" +
					"?parent=" + url.QueryEscape(response.Parent) +
					"&ext=" + url.QueryEscape(response.Ext) +
					"&oldName=" + url.QueryEscape(response.Name)
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":    "rename",
					"parent":  response.Parent,
					"ext":     response.Ext,
					"oldName": response.Name,
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
			request.Ext = r.Form.Get("ext")
			request.Name = r.Form.Get("oldName")
			request.ChangeTo = r.Form.Get("newName")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			FormErrors: make(url.Values),
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			Ext:        request.Ext,
			Name:       request.Name,
			NewName:    request.ChangeTo,
		}
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			for _, char := range response.NewName {
				if char >= 0 && char <= 31 {
					continue
				}
				n := int(char)
				if n >= len(isFilenameUnsafe) || !isFilenameUnsafe[n] {
					continue
				}
				response.FormErrors.Add("newName", fmt.Sprintf("cannot use %c", char))
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		case "pages", "posts", "output":
			for _, char := range response.NewName {
				if char >= 0 && char <= 31 {
					continue
				}
				n := int(char)
				if n >= len(isURLUnsafe) || !isURLUnsafe[n] {
					continue
				}
				response.FormErrors.Add("newName", fmt.Sprintf("cannot use %c", char))
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		oldPath := path.Join(response.SitePrefix, response.Parent, response.Name+response.Ext)
		newPath := path.Join(response.SitePrefix, response.Parent, response.NewName+response.Ext)
		fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), oldPath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		response.IsDir = fileInfo.IsDir()
		if response.IsDir && response.Ext == "" {
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), newPath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		} else {
			response.FormErrors.Add("newName", "a file with this name already exists")
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		err = nbrew.FS.WithContext(r.Context()).Rename(oldPath, newPath)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		// TODO: if head is pages or posts, we need to rename the outputDir as well.
		// TODO: if the file is one of pages/index.html | pages/404.html | themes/post.html | themes/postlist.html, we must treat it like we created a duplicate file and call copyDir over
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
