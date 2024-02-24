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
		Parent string `json:"parent"`
		Name   string `json:"name"`
		To     string `json:"to"`
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
		if name == "" || strings.Contains(name, "/") {
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes", "pages", "posts", "output":
			if response.Parent == "pages" && (name == "index.html" || name == "404.html") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			if response.Parent == "output/themes" && (name == "post.html" || name == "postlist.html") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, name))
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
		if response.IsDir {
			response.From = name
		} else {
			remainder := name
			if head == "posts" {
				i := strings.Index(remainder, "-")
				if i >= 0 {
					prefix, suffix := remainder[:i], remainder[i+1:]
					if len(prefix) > 0 && len(prefix) <= 8 {
						b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
						if len(b) == 5 {
							response.Prefix = prefix + "-"
							remainder = suffix
						}
					}
				}
			}
			ext := path.Ext(remainder)
			response.From = strings.TrimSuffix(remainder, ext)
			response.Ext = ext
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
					"&name=" + url.QueryEscape(response.Prefix+response.From+response.Ext)
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":    "rename",
					"parent":  response.Parent,
					"oldName": response.Prefix + response.From + response.Ext,
					"newName": response.Prefix + response.To + response.Ext,
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
			request.Name = r.Form.Get("name")
			request.To = r.Form.Get("to")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			FormErrors: make(url.Values),
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
		}
		if request.Name == "" || strings.Contains(request.Name, "/") {
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			for _, char := range response.To {
				if char >= 0 && char <= 31 {
					continue
				}
				n := int(char)
				if n >= len(isFilenameUnsafe) || !isFilenameUnsafe[n] {
					continue
				}
				response.FormErrors.Add("to", fmt.Sprintf("cannot include character %q", string(char)))
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		case "pages", "posts", "output":
			if response.Parent == "pages" && (request.Name == "index.html" || request.Name == "404.html") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			if response.Parent == "output/themes" && (request.Name == "post.html" || request.Name == "postlist.html") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			for _, char := range response.To {
				if char >= 0 && char <= 31 {
					continue
				}
				n := int(char)
				if n >= len(isURLUnsafe) || !isURLUnsafe[n] {
					continue
				}
				if char == ' ' {
					response.FormErrors.Add("to", fmt.Sprintf("cannot include space"))
				} else {
					response.FormErrors.Add("to", fmt.Sprintf("cannot include character %q", string(char)))
				}
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, request.Name))
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
		if response.IsDir {
			response.From = request.Name
		} else {
			remainder := request.Name
			ext := path.Ext(remainder)
			if head == "posts" && ext == ".md" {
				prefix, suffix, ok := strings.Cut(remainder, "-")
				if ok && len(prefix) > 0 && len(prefix) <= 8 {
					b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
					if len(b) == 5 {
						response.Prefix = prefix + "-"
						remainder = suffix
					}
				}
			}
			response.From = strings.TrimSuffix(remainder, ext)
			response.Ext = ext
		}
		_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, response.Parent, response.Prefix+response.To+response.Ext))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		} else {
			response.FormErrors.Add("to", "a file with this name already exists")
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		err = nbrew.FS.WithContext(r.Context()).Rename(
			path.Join(sitePrefix, response.Parent, response.Prefix+response.From+response.Ext),
			path.Join(sitePrefix, response.Parent, response.Prefix+response.To+response.Ext),
		)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		switch head {
		case "pages":
			err = nbrew.FS.WithContext(r.Context()).Rename(
				path.Join(sitePrefix, "output", tail, response.From),
				path.Join(sitePrefix, "output", tail, response.To),
			)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		case "posts":
			err = nbrew.FS.WithContext(r.Context()).Rename(
				path.Join(sitePrefix, "output/posts", tail, response.Prefix+response.From),
				path.Join(sitePrefix, "output/posts", tail, response.Prefix+response.To),
			)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
