package nb9

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yuin/goldmark"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) createfile(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Request struct {
		Parent  string
		Name    string
		Ext     string
		Content string
	}
	type Response struct {
		Error         string        `json:"error,omitempty"`
		FormErrors    url.Values    `json:"formErrors,omitempty"`
		TemplateError TemplateError `json:"templateError,omitempty"`
		ContentSite   string        `json:"contentSite"`
		Username      NullString    `json:"username"`
		SitePrefix    string        `json:"sitePrefix"`
		Parent        string        `json:"parent,omitempty"`
		Name          string        `json:"name,omitempty"`
		Ext           string        `json:"ext,omitempty"`
		Content       string        `json:"content,omitempty"`
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
			if next == "posts" {
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
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			response.Ext = ".txt"
		case "pages":
			response.Ext = ".html"
		case "posts":
			response.Ext = ".md"
		case "output":
			next, _, _ := strings.Cut(tail, "/")
			if next == "themes" {
				response.Ext = ".html"
			} else {
				response.Ext = ".css"
			}
		default:
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
				"postRedirectGet": map[string]any{
					"from":          "createfile",
					"templateError": response.TemplateError,
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent, response.Name+response.Ext), http.StatusFound)
		}

		var err error
		var request Request
		var reader *multipart.Reader
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			err := r.ParseForm()
			if err != nil {
				badRequest(w, r, err)
				return
			}
			request.Parent = r.Form.Get("parent")
			request.Name = r.Form.Get("name")
			request.Ext = r.Form.Get("ext")
			request.Content = r.Form.Get("content")
		case "multipart/form-data":
			r.Body = http.MaxBytesReader(w, r.Body, 25<<20 /* 25 MB */)
			reader, err = r.MultipartReader()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			var maxBytesErr *http.MaxBytesError
			for i := 0; i < 4; i++ {
				part, err := reader.NextPart()
				if err != nil {
					if err == io.EOF {
						break
					}
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				var b strings.Builder
				_, err = io.Copy(&b, part)
				if err != nil {
					if errors.As(err, &maxBytesErr) {
						badRequest(w, r, err)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				formName := part.FormName()
				switch formName {
				case "parent":
					request.Parent = b.String()
				case "name":
					request.Name = b.String()
				case "ext":
					request.Ext = b.String()
				case "content":
					request.Content = b.String()
				}
			}
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			FormErrors: make(url.Values),
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			Ext:        request.Ext,
			Content:    request.Content,
		}
		if !isValidParent(response.Parent) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		var outputDir string
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			if request.Name != "" {
				response.Name = filenameSafe(request.Name)
			} else {
				if response.Ext == ".md" || response.Ext == ".txt" {
					var line string
					remainder := response.Content
					for remainder != "" {
						line, remainder, _ = strings.Cut(remainder, "\n")
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}
						if response.Ext == ".md" {
							response.Name = filenameSafe(stripMarkdownStyles(goldmark.New(), []byte(line)))
						} else {
							response.Name = filenameSafe(line)
						}
						break
					}
				}
			}
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			if response.Ext != ".html" && response.Ext != ".css" && response.Ext != ".js" && response.Ext != ".md" && response.Ext != ".txt" {
				response.Ext = ".txt"
			}
		case "pages":
			if request.Name != "" {
				response.Name = urlSafe(request.Name)
			}
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
			outputDir = path.Join(sitePrefix, "output", tail, response.Name)
		case "posts":
			if request.Name != "" {
				response.Name = urlSafe(request.Name)
			} else {
				remainder := response.Content
				for remainder != "" {
					response.Name, remainder, _ = strings.Cut(remainder, "\n")
					response.Name = strings.TrimSpace(response.Name)
					if response.Name == "" {
						continue
					}
					response.Name = urlSafe(stripMarkdownStyles(goldmark.New(), []byte(response.Name)))
					break
				}
			}
			var timestamp [8]byte
			binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
			prefix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			if response.Name != "" {
				response.Name = prefix + "-" + response.Name
			} else {
				response.Name = prefix
			}
			if response.Ext != ".md" {
				response.Ext = ".md"
			}
			outputDir = path.Join(sitePrefix, "output/posts", tail, response.Name)
		case "output":
			if request.Name != "" {
				response.Name = urlSafe(request.Name)
			}
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			next, _, _ := strings.Cut(tail, "/")
			if next == "themes" {
				if response.Ext != ".html" && response.Ext != ".css" && response.Ext != ".js" && response.Ext != ".md" && response.Ext != ".txt" {
					response.Ext = ".html"
				}
			} else {
				if response.Ext != ".css" && response.Ext != ".js" && response.Ext != ".md" {
					response.Ext = ".css"
				}
			}
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, response.Parent, response.Name+response.Ext))
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
		writeFile := func(ctx context.Context, name string, reader io.Reader) error {
			writer, err := nbrew.FS.WithContext(ctx).OpenWriter(name, 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = io.Copy(writer, reader)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			return nil
		}
		if outputDir != "" {
			err := nbrew.FS.WithContext(r.Context()).MkdirAll(outputDir, 0755)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			if contentType == "multipart/form-data" {
				group, groupctx := errgroup.WithContext(r.Context())
				for {
					part, err := reader.NextPart()
					if err != nil {
						if err == io.EOF {
							break
						}
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
					if part.FormName() != "file" {
						continue
					}
					fileName := part.FileName()
					ext := path.Ext(fileName)
					if ext != ".jpeg" && ext != ".jpg" && ext != ".png" && ext != ".webp" && ext != ".gif" {
						continue
					}
					cmdPath, err := exec.LookPath("nbrew-process-img")
					if err != nil {
						err := writeFile(r.Context(), path.Join(outputDir, fileName), part)
						if err != nil {
							var maxBytesErr *http.MaxBytesError
							if errors.As(err, &maxBytesErr) {
								badRequest(w, r, err)
								return
							}
							getLogger(r.Context()).Error(err.Error())
							internalServerError(w, r, err)
							return
						}
						continue
					}
					randomID := NewID()
					inputFilePath := encodeUUID(randomID) + "-input" + ext
					outputFilePath := encodeUUID(randomID) + "-output" + ext
					tempDir, err := filepath.Abs(filepath.Join(os.TempDir(), "notebrew-temp"))
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
					inputFile, err := os.OpenFile(filepath.Join(tempDir, inputFilePath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
					_, err = io.Copy(inputFile, part)
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
					err = inputFile.Close()
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
					group.Go(func() error {
						defer os.Remove(inputFilePath)
						defer os.Remove(outputFilePath)
						cmd := exec.CommandContext(groupctx, cmdPath, inputFilePath, outputFilePath)
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stderr
						err := cmd.Run()
						if err != nil {
							return err
						}
						outputFile, err := os.Open(outputFilePath)
						if err != nil {
							return err
						}
						err = writeFile(groupctx, path.Join(outputDir, fileName), outputFile)
						if err != nil {
							return err
						}
						return nil
					})
				}
				err := group.Wait()
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
		}
		switch head {
		case "pages":
			siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			err = siteGen.GeneratePage(r.Context(), path.Join(response.Parent, response.Name+response.Ext), response.Content)
			if err != nil {
				if !errors.As(err, &response.TemplateError) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
		case "posts":
			siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			var templateErrPtr atomic.Pointer[TemplateError]
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				var templateErr TemplateError
				tmpl, err := siteGen.PostTemplate(groupctx)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				err = siteGen.GeneratePost(groupctx, path.Join(response.Parent, response.Name+response.Ext), response.Content, tmpl)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				return nil
			})
			group.Go(func() error {
				var templateErr TemplateError
				category := tail
				tmpl, err := siteGen.PostListTemplate(groupctx, category)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				_, err = siteGen.GeneratePostList(r.Context(), category, tmpl)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				return nil
			})
			err = group.Wait()
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
