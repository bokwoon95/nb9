package nb9

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/nb9/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) regenerate(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	type Response struct {
		Count          int      `json:"count"`
		TimeTaken      string   `json:"timeTaken"`
		TemplateErrors []string `json:"templateErrors,omitempty"`
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
		err := nbrew.setSession(w, r, "flash", map[string]any{
			"postRedirectGet": map[string]any{
				"from":           "regenerate",
				"count":          response.Count,
				"timeTaken":      response.TimeTaken,
				"templateErrors": response.TemplateErrors,
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
	}

	if r.Method != "POST" {
		methodNotAllowed(w, r)
		return
	}
	siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
		type File struct {
			FilePath string
			IsDir    bool
			Text     string
		}
		var response Response
		var count atomic.Int64
		startedAt := time.Now()
		g1, ctx1 := errgroup.WithContext(r.Context())
		g1.Go(func() error {
			cursor, err := sq.FetchCursor(ctx1, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE file_path LIKE {pattern} ESCAPE '\\'" +
					" AND (NOT is_dir AND file_path LIKE '%.html')",
				Values: []any{
					sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(path.Join(sitePrefix, "pages"))+"/%"),
				},
			}, func(row *sq.Row) File {
				return File{
					FilePath: row.String("file_path"),
					Text:     row.String("text"),
				}
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			g2, ctx2 := errgroup.WithContext(ctx1)
			for cursor.Next() {
				file, err := cursor.Result()
				if err != nil {
					return err
				}
				g2.Go(func() error {
					if sitePrefix != "" {
						file.FilePath = strings.TrimPrefix(file.FilePath, sitePrefix+"/")
					}
					count.Add(1)
					return siteGen.GeneratePage(ctx2, file.FilePath, file.Text)
				})
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
			err = g2.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		g1.Go(func() error {
			postTemplate, err := siteGen.PostTemplate(ctx1)
			if err != nil {
				return err
			}
			cursor, err := sq.FetchCursor(ctx1, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE (file_path = {posts} OR file_path LIKE {pattern} ESCAPE '\\')" +
					" AND (is_dir OR file_path LIKE '%.md')",
				Values: []any{
					sq.StringParam("posts", path.Join(sitePrefix, "posts")),
					sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(path.Join(sitePrefix, "posts"))+"/%"),
				},
			}, func(row *sq.Row) File {
				return File{
					FilePath: row.String("file_path"),
					IsDir:    row.Bool("is_dir"),
					Text:     row.String("text"),
				}
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			g2, ctx2 := errgroup.WithContext(ctx1)
			for cursor.Next() {
				file, err := cursor.Result()
				if err != nil {
					return err
				}
				g2.Go(func() error {
					if sitePrefix != "" {
						file.FilePath = strings.TrimPrefix(file.FilePath, sitePrefix+"/")
					}
					if !file.IsDir {
						count.Add(1)
						return siteGen.GeneratePost(ctx2, file.FilePath, file.Text, postTemplate)
					}
					_, category, _ := strings.Cut(file.FilePath, "/")
					if strings.Contains(category, "/") {
						return nil
					}
					postListTemplate, err := siteGen.PostListTemplate(ctx2, category)
					if err != nil {
						return err
					}
					n, err := siteGen.GeneratePostList(ctx2, category, postListTemplate)
					count.Add(int64(n))
					if err != nil {
						return err
					}
					return nil
				})
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
			err = g2.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		err = g1.Wait()
		if err != nil {
			var parseErr TemplateParseError
			var executionErr *TemplateExecutionError
			if errors.As(err, &parseErr) {
				response.TemplateErrors = append(response.TemplateErrors, parseErr.List()...)
			} else if errors.As(err, &executionErr) {
				response.TemplateErrors = append(response.TemplateErrors, executionErr.Err.Error())
			} else {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		response.Count = int(count.Load())
		response.TimeTaken = time.Since(startedAt).String()
		writeResponse(w, r, response)
		return
	}
	var response Response
	var count atomic.Int64
	startedAt := time.Now()
	g1, ctx1 := errgroup.WithContext(r.Context())
	g1.Go(func() error {
		g2, ctx2 := errgroup.WithContext(ctx1)
		root := path.Join(sitePrefix, "pages")
		err := fs.WalkDir(nbrew.FS.WithContext(ctx1), root, func(filePath string, dirEntry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if filePath == root {
				return nil
			}
			g2.Go(func() error {
				file, err := nbrew.FS.WithContext(ctx2).Open(filePath)
				if err != nil {
					return err
				}
				fileInfo, err := file.Stat()
				if err != nil {
					return err
				}
				if fileInfo.IsDir() || !strings.HasSuffix(filePath, ".html") {
					return nil
				}
				var b strings.Builder
				b.Grow(int(fileInfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					return err
				}
				if sitePrefix != "" {
					filePath = strings.TrimPrefix(filePath, sitePrefix+"/")
				}
				count.Add(1)
				return siteGen.GeneratePage(ctx2, filePath, b.String())
			})
			return nil
		})
		err = g2.Wait()
		if err != nil {
			return err
		}
		if err != nil {
			return err
		}
		return nil
	})
	g1.Go(func() error {
		postTemplate, err := siteGen.PostTemplate(ctx1)
		if err != nil {
			return err
		}
		g2, ctx2 := errgroup.WithContext(ctx1)
		root := path.Join(sitePrefix, "posts")
		err = fs.WalkDir(nbrew.FS.WithContext(ctx1), root, func(filePath string, dirEntry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			g2.Go(func() error {
				if !dirEntry.IsDir() {
					if !strings.HasSuffix(filePath, ".md") {
						return nil
					}
					file, err := nbrew.FS.WithContext(ctx2).Open(filePath)
					if err != nil {
						return err
					}
					fileInfo, err := file.Stat()
					if err != nil {
						return err
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						return err
					}
					if sitePrefix != "" {
						filePath = strings.TrimPrefix(filePath, sitePrefix+"/")
					}
					count.Add(1)
					return siteGen.GeneratePost(ctx2, filePath, b.String(), postTemplate)
				}
				if sitePrefix != "" {
					filePath = strings.TrimPrefix(filePath, sitePrefix+"/")
				}
				_, category, _ := strings.Cut(filePath, "/")
				if strings.Contains(category, "/") {
					return nil
				}
				postListTemplate, err := siteGen.PostListTemplate(ctx2, category)
				if err != nil {
					return err
				}
				n, err := siteGen.GeneratePostList(ctx2, category, postListTemplate)
				count.Add(int64(n))
				if err != nil {
					return err
				}
				return nil
			})
			return nil
		})
		err = g2.Wait()
		if err != nil {
			return err
		}
		if err != nil {
			return err
		}
		return nil
	})
	err = g1.Wait()
	response.Count = int(count.Load())
	response.TimeTaken = time.Since(startedAt).String()
	if err != nil {
		var parseErr TemplateParseError
		var executionErr *TemplateExecutionError
		if errors.As(err, &parseErr) {
			response.TemplateErrors = append(response.TemplateErrors, parseErr.List()...)
		} else if errors.As(err, &executionErr) {
			response.TemplateErrors = append(response.TemplateErrors, executionErr.Err.Error())
		} else {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
	}
	writeResponse(w, r, response)
}

func (nbrew *Notebrew) regeneratelist(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	type Request struct {
		Category string
	}
	type Response struct {
		Category       string   `json:"category,omitempty"`
		Count          int      `json:"count"`
		TimeTaken      string   `json:"timeTaken"`
		TemplateErrors []string `json:"templateErrors,omitempty"`
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
		if strings.Contains(response.Category, "/") {
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "posts")+"/", http.StatusFound)
			return
		}
		err := nbrew.setSession(w, r, "flash", map[string]any{
			"postRedirectGet": map[string]any{
				"from":           "regeneratelist",
				"category":       response.Category,
				"count":          response.Count,
				"timeTaken":      response.TimeTaken,
				"templateErrors": response.TemplateErrors,
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "posts", response.Category)+"/", http.StatusFound)
	}
	if r.Method != "POST" {
		methodNotAllowed(w, r)
		return
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
		request.Category = r.Form.Get("category")
	default:
		unsupportedContentType(w, r)
		return
	}

	response := Response{
		Category: request.Category,
	}
	if strings.Contains(response.Category, "/") {
		writeResponse(w, r, response)
		return
	}
	siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	tmpl, err := siteGen.PostListTemplate(r.Context(), response.Category)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	startedAt := time.Now()
	response.Count, err = siteGen.GeneratePostList(r.Context(), response.Category, tmpl)
	response.TimeTaken = time.Since(startedAt).String()
	if err != nil {
		var parseErr TemplateParseError
		var executionErr *TemplateExecutionError
		if errors.As(err, &parseErr) {
			response.TemplateErrors = append(response.TemplateErrors, parseErr.List()...)
		} else if errors.As(err, &executionErr) {
			response.TemplateErrors = append(response.TemplateErrors, executionErr.Err.Error())
		} else {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
	}
	writeResponse(w, r, response)
}
