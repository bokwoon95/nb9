package nb9

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"
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
	r.Body = http.MaxBytesReader(w, r.Body, 25<<20 /* 25 MB */)
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
	head, tail, _ := strings.Cut(response.Parent, "/")
	if head != "notes" && head != "pages" && head != "posts" {
		next, _, _ := strings.Cut(tail, "/")
		if head != "output" || next != "themes" {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
	}
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
		filePath := params["filename"]
		dir, name := path.Split(filePath)
		if dir != "" {
			continue
		}
		name = filenameSafe(name)
		ext := path.Ext(name)
		switch head {
		case "pages":
			if ext != ".html" {
				continue
			}
		case "posts":
			if ext != ".md" {
				continue
			}
			// TODO: if we paste markdown files here, we need to prepend the timestamp prefix to the name.
		default:
			if ext != ".jpeg" && ext != ".jpg" && ext != ".png" && ext != ".webp" && ext != ".gif" &&
				ext != ".html" && ext != ".css" && ext != ".js" && ext != ".md" && ext != ".txt" {
				continue
			}
		}
		// TODO: check if the file extension is valid.
		// TODO: if extension is an image, stream the part into memory then use golang's stdlib to resize it (consult ChatGPT and Google).
		err = func() error {
			writer, err := nbrew.FS.WithContext(r.Context()).OpenWriter(path.Join(sitePrefix, response.Parent, name), 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			n, err := io.Copy(writer, part)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			response.Count++
			response.Size += int(n)
			return nil
		}()
		// TODO: if we paste markdown files in posts, we need to call RegeneratePost and RegeneratePostList as well.
		if err != nil {
			response.Error = err.Error()
			return
		}
	}
	writeResponse(w, r, response)
}
