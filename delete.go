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
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
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
		Error        string     `json:"status"`
		DeleteErrors []string   `json:"deleteErrors,omitempty"`
		ContentSite  string     `json:"contentSite,omitempty"`
		Username     NullString `json:"username"`
		SitePrefix   string     `json:"sitePrefix"`
		Parent       string     `json:"parent,omitempty"`
		Files        []File     `json:"files,omitempty"`
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
		g, ctx := errgroup.WithContext(r.Context())
		names := r.Form["name"]
		response.Files = make([]File, len(names))
		for i, name := range names {
			i, name := i, filepath.ToSlash(name)
			if strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			g.Go(func() error {
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(ctx), path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
				}
				response.Files[i] = File{
					Name:    fileInfo.Name(),
					IsDir:   fileInfo.IsDir(),
					Size:    fileInfo.Size(),
					ModTime: fileInfo.ModTime(),
				}
				return nil
			})
		}
		err = g.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		n := 0
		for _, file := range response.Files {
			if file.Name == "" {
				continue
			}
			response.Files[n] = file
			n++
		}
		response.Files = response.Files[:n]
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
					"from":       "delete",
					"numDeleted": len(response.Files),
					"numErrors":  len(response.DeleteErrors),
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
		g, ctx := errgroup.WithContext(r.Context())
		response.DeleteErrors = make([]string, len(request.Names))
		response.Files = make([]File, len(request.Names))
		for i, name := range request.Names {
			i, name := i, filepath.ToSlash(name)
			if strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			g.Go(func() error {
				err := nbrew.FS.WithContext(ctx).RemoveAll(path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					response.DeleteErrors[i] = fmt.Sprintf("%s: %v", name, err)
				} else {
					response.Files[i] = File{Name: name}
				}
				head, tail, _ := strings.Cut(response.Parent, "/")
				switch head {
				case "pages":
					if tail != "" || name != "index.html" {
						err := nbrew.FS.WithContext(ctx).RemoveAll(path.Join(sitePrefix, "output", tail, strings.TrimSuffix(name, path.Ext(name))))
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
					}
					file, err := RuntimeFS.Open("embed/index.html")
					if err != nil {
						getLogger(ctx).Error(err.Error())
						return nil
					}
					defer file.Close()
					writer, err := nbrew.FS.WithContext(ctx).OpenWriter(path.Join(sitePrefix, "pages/index.html"), 0644)
					if err != nil {
						getLogger(ctx).Error(err.Error())
						return nil
					}
					defer writer.Close()
					_, err = io.Copy(writer, file)
					if err != nil {
						getLogger(ctx).Error(err.Error())
						return nil
					}
					err = writer.Close()
					if err != nil {
						getLogger(ctx).Error(err.Error())
						return nil
					}
				case "posts":
					err := nbrew.FS.WithContext(ctx).RemoveAll(path.Join(sitePrefix, "output", response.Parent, strings.TrimSuffix(name, path.Ext(name))))
					if err != nil {
						getLogger(ctx).Error(err.Error())
						return nil
					}
					if strings.HasSuffix(name, ".md") {
						siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
						category := tail
						tmpl, err := siteGen.PostListTemplate(r.Context(), category)
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
						_, err = siteGen.GeneratePostList(r.Context(), category, tmpl)
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
					}
				case "output":
					if tail != "themes" {
						return nil
					}
					switch name {
					case "post.html":
						file, err := RuntimeFS.Open("embed/post.html")
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
						defer file.Close()
						writer, err := nbrew.FS.WithContext(ctx).OpenWriter(path.Join(sitePrefix, "output/themes/post.html"), 0644)
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
						defer writer.Close()
						_, err = io.Copy(writer, file)
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
						err = writer.Close()
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
					case "postlist.html":
						file, err := RuntimeFS.Open("embed/postlist.html")
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
						defer file.Close()
						writer, err := nbrew.FS.WithContext(ctx).OpenWriter(path.Join(sitePrefix, "output/themes/postlist.html"), 0644)
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
						defer writer.Close()
						_, err = io.Copy(writer, file)
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
						err = writer.Close()
						if err != nil {
							getLogger(ctx).Error(err.Error())
							return nil
						}
					}
				}
				return nil
			})
		}
		err := g.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		n := 0
		for _, file := range response.Files {
			if file.Name == "" {
				continue
			}
			response.Files[n] = file
			n++
		}
		response.Files = response.Files[:n]
		n = 0
		for _, errmsg := range response.DeleteErrors {
			if errmsg == "" {
				continue
			}
			response.DeleteErrors[n] = errmsg
			n++
		}
		response.DeleteErrors = response.DeleteErrors[:n]
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
