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
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) uploadfile(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Response struct {
		Error         string        `json:"error,omitempty"`
		Parent        string        `json:"parent"`
		Count         int           `json:"count"`
		Size          int           `json:"size"`
		FilesExist    []string      `json:"fileExist,omitempty"`
		FilesTooBig   []string      `json:"filesTooBig,omitempty"`
		TemplateError TemplateError `json:"templateError"`
	}
	if r.Method != "POST" {
		methodNotAllowed(w, r)
		return
	}
	referer := r.Referer()
	if referer == "" {
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
		return
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
				"from":          "uploadfile",
				"error":         response.Error,
				"count":         response.Count,
				"size":          response.Size,
				"templateError": response.TemplateError,
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, referer, http.StatusFound)
	}
	if nbrew.UsersDB != nil {
		// TODO: calculate the available storage space of the owner and add
		// it as a MaxBytesReader to the request body.
		//
		// TODO: but then: how do we differentiate between a MaxBytesError
		// returned by a file exceeding 10 MB vs a MaxBytesError returned
		// by the request body exceeding available storage space? Maybe if
		// maxBytesErr is 10 MB we assume it's a file going over the limit,
		// otherwise we assume it's the owner exceeding his storage space?
	}

	reader, err := r.MultipartReader()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	var response Response
	part, err := reader.NextPart()
	if err != nil {
		if err == io.EOF {
			response.Error = "ParentNotFound"
			writeResponse(w, r, response)
			return
		}
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	formName := part.FormName()
	if formName != "parent" {
		response.Error = "ParentNotFound"
		writeResponse(w, r, response)
		return
	}
	var b strings.Builder
	_, err = io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
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
	response.Parent = b.String()

	var siteGen *SiteGenerator
	var postTemplate *template.Template
	var templateErrPtr atomic.Pointer[TemplateError]
	head, tail, _ := strings.Cut(response.Parent, "/")
	switch head {
	case "notes":
		break
	case "pages":
		siteGen, err = NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
	case "posts":
		siteGen, err = NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		postTemplate, err = siteGen.PostTemplate(r.Context())
		if err != nil {
			var templateErr TemplateError
			if !errors.As(err, &templateErr) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			templateErrPtr.CompareAndSwap(nil, &templateErr)
		}
	case "output":
		next, _, _ := strings.Cut(tail, "/")
		if next != "themes" {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
	default:
		response.Error = "InvalidParent"
		writeResponse(w, r, response)
		return
	}

	var count, size atomic.Int64
	writeFile := func(ctx context.Context, filePath string, reader io.Reader) error {
		writer, err := nbrew.FS.WithContext(ctx).OpenWriter(filePath, 0644)
		if err != nil {
			return err
		}
		defer writer.Close()
		n, err := io.Copy(writer, reader)
		if err != nil {
			_ = nbrew.FS.WithContext(ctx).Remove(filePath)
			return err
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		count.Add(1)
		size.Add(n)
		return nil
	}

	tempDir, err := filepath.Abs(filepath.Join(os.TempDir(), "notebrew-temp"))
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
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
		formName := part.FormName()
		if formName != "file" {
			continue
		}
		_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil {
			continue
		}
		fileName := params["filename"]
		if strings.Contains(fileName, "/") {
			continue
		}
		fileName = filenameSafe(fileName)
		filePath := path.Join(sitePrefix, response.Parent, fileName)
		_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), filePath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		} else {
			response.FilesExist = append(response.FilesExist, fileName)
			continue
		}
		ext := path.Ext(fileName)

		// Since we don't do any image processing or page/post generation
		// for notes, we can stream the file directly into the filesystem.
		if head == "notes" {
			switch ext {
			case ".jpeg", ".jpg", ".png", ".webp", ".gif":
				err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, 10<<20 /* 10 MB */))
				if err != nil {
					var maxBytesErr *http.MaxBytesError
					if errors.As(err, &maxBytesErr) {
						response.FilesTooBig = append(response.FilesTooBig, fileName)
						continue
					}
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			case ".html", ".css", ".js", ".md", ".txt":
				err := writeFile(r.Context(), path.Join(sitePrefix, response.Parent, fileName), http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
				if err != nil {
					var maxBytesErr *http.MaxBytesError
					if errors.As(err, &maxBytesErr) {
						response.FilesTooBig = append(response.FilesTooBig, fileName)
						continue
					}
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
			continue
		}

		if head == "pages" {
			if ext != ".html" {
				continue
			}
			var b strings.Builder
			_, err := io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
			if err != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					response.FilesTooBig = append(response.FilesTooBig, fileName)
					continue
				}
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			text := b.String()
			group.Go(func() error {
				err := writeFile(groupctx, filePath, strings.NewReader(text))
				if err != nil {
					return err
				}
				err = siteGen.GeneratePage(groupctx, filePath, text)
				if err != nil {
					var templateErr TemplateError
					if !errors.As(err, &templateErr) {
						return err
					}
					templateErrPtr.CompareAndSwap(nil, &templateErr)
				}
				return nil
			})
			continue
		}

		if head == "posts" {
			if ext != ".md" {
				continue
			}
			var b strings.Builder
			_, err := io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
			if err != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					response.FilesTooBig = append(response.FilesTooBig, fileName)
					continue
				}
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			text := b.String()
			group.Go(func() error {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				prefix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
				if strings.TrimSuffix(fileName, ext) != "" {
					fileName = prefix + "-" + fileName
				} else {
					fileName = prefix + fileName
				}
				err := writeFile(groupctx, filePath, strings.NewReader(text))
				if err != nil {
					return err
				}
				err = siteGen.GeneratePost(groupctx, filePath, text, postTemplate)
				if err != nil {
					var templateErr TemplateError
					if !errors.As(err, &templateErr) {
						return err
					}
					templateErrPtr.CompareAndSwap(nil, &templateErr)
				}
				return nil
			})
			continue
		}

		switch ext {
		case ".jpeg", ".jpg", ".png", ".webp", ".gif":
			cmdPath, err := exec.LookPath("nbrew-process-img")
			if err != nil {
				err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, 10<<20 /* 10 MB */))
				if err != nil {
					var maxBytesErr *http.MaxBytesError
					if errors.As(err, &maxBytesErr) {
						response.FilesTooBig = append(response.FilesTooBig, fileName)
						continue
					}
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				continue
			}
			id := NewID()
			inputPath := path.Join(tempDir, encodeUUID(id)+"-input"+ext)
			outputPath := path.Join(tempDir, encodeUUID(id)+"-output"+ext)
			input, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				err := os.MkdirAll(filepath.Dir(inputPath), 0755)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				input, err = os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
			_, err = io.Copy(input, http.MaxBytesReader(nil, part, 10<<20 /* 10 MB */))
			if err != nil {
				os.Remove(inputPath)
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					response.FilesTooBig = append(response.FilesTooBig, fileName)
					continue
				}
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			err = input.Close()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			group.Go(func() error {
				defer os.Remove(inputPath)
				defer os.Remove(outputPath)
				cmd := exec.CommandContext(groupctx, cmdPath, inputPath, outputPath)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				err := cmd.Run()
				if err != nil {
					return err
				}
				output, err := os.Open(outputPath)
				if err != nil {
					return err
				}
				err = writeFile(groupctx, filePath, output)
				if err != nil {
					return err
				}
				return nil
			})
			continue
		case ".html", ".css", ".js", ".md", ".txt":
			err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
			if err != nil {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					response.FilesTooBig = append(response.FilesTooBig, fileName)
					continue
				}
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			continue
		}
	}
	err = group.Wait()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	if head == "posts" {
		category := tail
		err := func() error {
			postListTemplate, err := siteGen.PostListTemplate(r.Context(), category)
			if err != nil {
				return err
			}
			_, err = siteGen.GeneratePostList(r.Context(), category, postListTemplate)
			if err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			var templateErr TemplateError
			if !errors.As(err, &templateErr) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			templateErrPtr.CompareAndSwap(nil, &templateErr)
		}
	}
	response.Count = int(count.Load())
	response.Size = int(size.Load())
	templateErr := templateErrPtr.Load()
	if templateErr != nil {
		response.TemplateError = *templateErr
	}
	writeResponse(w, r, response)
}
