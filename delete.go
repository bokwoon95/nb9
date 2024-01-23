package nb9

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (nbrew *Notebrew) delete(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
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
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"stylesCSS":  func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS": func() template.JS { return template.JS(baselineJS) },
				"referer":    func() string { return referer },
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
		seen := make(map[string]bool)
		fsys := nbrew.FS.WithContext(r.Context())
		for _, name := range r.Form["name"] {
			name = filepath.ToSlash(name)
			if strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			fileInfo, err := fs.Stat(fsys, path.Join(sitePrefix, response.Parent, name))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			response.Files = append(response.Files, File{
				Name:    fileInfo.Name(),
				IsDir:   fileInfo.IsDir(),
				Size:    fileInfo.Size(),
				ModTime: fileInfo.ModTime(),
			})
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
			var b strings.Builder
			if len(response.Files) == 1 {
				b.WriteString("1 file deleted")
			} else {
				b.WriteString(strconv.Itoa(len(response.Files)) + " files deleted")
			}
			if len(response.Errors) == 1 {
				b.WriteString(" (1 error)")
			} else if len(response.Errors) > 1 {
				b.WriteString(" (" + strconv.Itoa(len(response.Errors)) + " errors)")
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
		seen := make(map[string]bool)
		// TODO: if any of the files are pages/index.html,
		// output/themes/post.html and output/themes/postlist.html then
		// regenerate those files from RuntimeFS.
		fsys := nbrew.FS.WithContext(r.Context())
		regenerateFile := func(sitePrefix, destName, srcName string) error {
			file, err := RuntimeFS.Open(srcName)
			if err != nil {
				return err
			}
			defer file.Close()
			writer, err := fsys.OpenWriter(path.Join(sitePrefix, destName), 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = io.Copy(writer, file)
			if err != nil {
				return err
			}
			return writer.Close()
		}
		for _, name := range request.Names {
			name = filepath.ToSlash(name)
			if strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			err := fsys.RemoveAll(path.Join(sitePrefix, response.Parent, name))
			if err != nil {
				response.Errors = append(response.Errors, fmt.Sprintf("%s: %v", name, err))
			} else {
				response.Files = append(response.Files, File{Name: name})
			}
			head, tail, _ := strings.Cut(response.Parent, "/")
			switch head {
			case "pages":
				if tail == "" && name == "index.html" {
					err := regenerateFile(sitePrefix, "pages/index.html", "embed/index.html")
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
					}
				} else {
					err := fsys.RemoveAll(path.Join(sitePrefix, "output", tail, strings.TrimSuffix(name, path.Ext(name))))
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
					}
				}
			case "posts":
				err := fsys.RemoveAll(path.Join(sitePrefix, "output", response.Parent, strings.TrimSuffix(name, path.Ext(name))))
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
			case "output":
				if tail == "themes" {
					if name == "post.html" {
						err := regenerateFile(sitePrefix, "output/themes/post.html", "embed/post.html")
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
						}
					} else if name == "postlist.html" {
						err := regenerateFile(sitePrefix, "output/themes/postlist.html", "embed/postlist.html")
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
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
