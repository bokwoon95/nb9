package nb9

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"os/exec"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) uploadfile(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Response struct {
		Error  string `json:"error,omitempty"`
		Parent string `json:"parent"`
		Count  int    `json:"count"`
		Size   int    `json:"size"`
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
				"from":  "uploadfile",
				"error": response.Error,
				"count": response.Count,
				"size":  response.Size,
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, referer, http.StatusFound)
	}

	r.Body = http.MaxBytesReader(w, r.Body, 25<<20 /* 25 MB */)
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
			response.Error = "NoFilesProvided"
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
	b, err := io.ReadAll(part)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	response.Parent = string(b)

	var siteGen *SiteGenerator
	var postTemplate *template.Template
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
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
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
	writeFile := func(ctx context.Context, name string, reader io.Reader) error {
		writer, err := nbrew.FS.WithContext(ctx).OpenWriter(name, 0644)
		if err != nil {
			return err
		}
		defer writer.Close()
		n, err := io.Copy(writer, reader)
		if err != nil {
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

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	group, groupctx := errgroup.WithContext(ctx)
	for {
		part, err := reader.NextPart()
		if err != nil {
			if err == io.EOF {
				break
			}
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				badRequest(w, r, err)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil {
			params = nil
		}
		name := params["filename"]
		if strings.Contains(name, "/") {
			continue
		}
		name = filenameSafe(name)
		ext := path.Ext(name)

		// Since we don't do any image processing or page/post generation
		// for notes, we can stream the file directly into the filesystem.
		if head == "notes" {
			switch ext {
			case ".jpeg", ".jpg", ".png", ".webp", ".gif", ".html", ".css", ".js", ".md", ".txt":
				err := writeFile(r.Context(), path.Join(sitePrefix, response.Parent, name), part)
				if err != nil {
					getLogger(groupctx).Error(err.Error())
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
			_, err := io.Copy(&b, part)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			text := b.String()
			group.Go(func() error {
				filePath := path.Join(sitePrefix, response.Parent, name)
				err := writeFile(groupctx, filePath, strings.NewReader(text))
				if err != nil {
					return err
				}
				err = siteGen.GeneratePage(groupctx, filePath, text)
				if err != nil {
					return err
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
			_, err := io.Copy(&b, part)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			text := b.String()
			group.Go(func() error {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				prefix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
				if strings.TrimSuffix(name, ext) != "" {
					name = prefix + "-" + name
				} else {
					name = prefix + name
				}
				filePath := path.Join(sitePrefix, response.Parent, name)
				err := writeFile(groupctx, filePath, strings.NewReader(text))
				if err != nil {
					return err
				}
				err = siteGen.GeneratePost(groupctx, filePath, text, postTemplate)
				if err != nil {
					return err
				}
				return nil
			})
			continue
		}

		switch ext {
		case ".jpeg", ".jpg", ".png", ".webp", ".gif":
			cmdPath, err := exec.LookPath("nbrew-process-img")
			if err != nil {
				err := writeFile(r.Context(), path.Join(sitePrefix, response.Parent, name), part)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				continue
			}
			// TODO: stream part into $TMPDIR/$RANDOMID-input.jpeg, then kick
			// off a group.Go() that calls `nbrew-process-img
			// $TMPDIR/$RANDOMID-input.jpeg $TMPDIR/$RANDOMID-output.jpeg` and
			// then stream $TMPDIR/$RANDOMID-output.jpeg into the filesystem
			// and delete both files.
			_ = cmdPath
			continue
		case ".html", ".css", ".js", ".md", ".txt":
			err := writeFile(r.Context(), path.Join(sitePrefix, response.Parent, name), part)
			if err != nil {
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
		postListTemplate, err := siteGen.PostListTemplate(r.Context(), category)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		_, err = siteGen.GeneratePostList(r.Context(), category, postListTemplate)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
	}
	response.Count = int(count.Load())
	response.Size = int(size.Load())
	writeResponse(w, r, response)
}
