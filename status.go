package nb9

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

type Status string

// TODO: rethink the error system when you get into it.
const (
	Success       = Status("Success")
	UpdateSuccess = Status("UpdateSuccess")

	ErrBadRequest           = Status("BadRequest")
	ErrNotAuthenticated     = Status("NotAuthenticated")
	ErrNotAuthorized        = Status("NotAuthorized")
	ErrNotFound             = Status("NotFound")
	ErrMethodNotAllowed     = Status("MethodNotAllowed")
	ErrUnsupportedMediaType = Status("UnsupportedMediaType")
	ErrServerError          = Status("ServerError")
)

func (s Status) Error() string {
	return string(s)
}

func (s Status) Code() string {
	n := strings.Index(string(s), ":")
	if n < 0 {
		return string(s)
	}
	return string(s[:n])
}

func (s Status) Equal(target Status) bool {
	code := s.Code()
	if code != "" {
		return code == target.Code()
	}
	return string(s) == string(target)
}

func (s Status) Is(target error) bool {
	if target, ok := target.(Status); ok {
		return s.Equal(target)
	}
	return false
}

// TODO: move the below to notebrew.go

var errorTemplate = template.Must(template.
	New("error.html").
	Funcs(map[string]any{
		"safeHTML": func(v any) template.HTML {
			if str, ok := v.(string); ok {
				return template.HTML(str)
			}
			return ""
		},
	}).
	ParseFS(rootFS, "embed/error.html"),
)

func fileSizeToString(size int64) string {
	// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
	if size < 0 {
		return ""
	}
	const unit = 1000
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "kMGTPE"[exp])
}

func badRequest(w http.ResponseWriter, r *http.Request, serverErr error) {
	var msg string
	var maxBytesErr *http.MaxBytesError
	if errors.As(serverErr, &maxBytesErr) {
		msg = "the data you are sending is too big (max " + fileSizeToString(maxBytesErr.Limit) + ")"
	} else {
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType == "application/json" {
			if serverErr == io.EOF {
				msg = "missing JSON body"
			} else if serverErr == io.ErrUnexpectedEOF {
				msg = "malformed JSON"
			} else {
				msg = serverErr.Error()
			}
		} else {
			msg = serverErr.Error()
		}
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		serverErr = encoder.Encode(map[string]any{
			"status": string(ErrBadRequest) + ": " + msg,
		})
		if serverErr != nil {
			getLogger(r.Context()).Error(serverErr.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	err := errorTemplate.Execute(buf, map[string]any{
		"Title":    `400 bad request`,
		"Headline": "400 bad request",
		"Byline":   msg,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrBadRequest)+": "+msg, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusBadRequest)
	buf.WriteTo(w)
}

func notAuthenticated(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": ErrNotAuthenticated,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	var query string
	if r.Method == "GET" {
		if r.URL.RawQuery != "" {
			query = "?redirect=" + url.QueryEscape(r.URL.Path+"?"+r.URL.RawQuery)
		} else {
			query = "?redirect=" + url.QueryEscape(r.URL.Path)
		}
	}
	err := errorTemplate.Execute(buf, map[string]any{
		"Title":    `401 unauthorized`,
		"Headline": "401 unauthorized",
		"Byline":   fmt.Sprintf(`You are not authenticated, please <a href="/users/login/%s">log in</a>.`, query),
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrNotAuthenticated), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusUnauthorized)
	buf.WriteTo(w)
}

func notAuthorized(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": ErrNotAuthorized,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  r.Referer(),
		"Title":    "403 forbidden",
		"Headline": "403 forbidden",
		"Byline":   "You do not have permission to view this page (try logging in to a different account).",
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrNotAuthorized), http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusForbidden)
	buf.WriteTo(w)
}

func notFound(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": ErrNotFound,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  r.Referer(),
		"Title":    "404 not found",
		"Headline": "404 not found",
		"Byline":   "The page you are looking for does not exist.",
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrNotFound), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusNotFound)
	buf.WriteTo(w)
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": string(ErrMethodNotAllowed) + ": " + r.Method,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  r.Referer(),
		"Title":    "405 method not allowed",
		"Headline": "405 method not allowed: " + r.Method,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrNotFound), http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusMethodNotAllowed)
	buf.WriteTo(w)
}

func unsupportedContentType(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	var msg string
	if contentType == "" {
		msg = "missing Content-Type"
	} else {
		msg = "unsupported Content-Type: " + contentType
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": ErrUnsupportedMediaType.Code() + " " + msg,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  r.Referer(),
		"Title":    "415 unsupported media type",
		"Headline": msg,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, ErrUnsupportedMediaType.Code()+" "+msg, http.StatusUnsupportedMediaType)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusUnsupportedMediaType)
	buf.WriteTo(w)
}

func internalServerError(w http.ResponseWriter, r *http.Request, serverErr error) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": ErrServerError,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	var data map[string]any
	if errors.Is(serverErr, context.DeadlineExceeded) {
		data = map[string]any{
			"Referer":  r.Referer(),
			"Title":    "deadline exceeded",
			"Headline": "The server took too long to respond.",
		}
	} else {
		data = map[string]any{
			"Referer":  r.Referer(),
			"Title":    "500 internal server error",
			"Headline": "500 internal server error",
			"Byline":   "There's a bug with notebrew.",
			"Details":  serverErr.Error(),
		}
	}
	err := errorTemplate.Execute(buf, data)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusInternalServerError)
	buf.WriteTo(w)
}
