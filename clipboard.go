package nb9

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) clipboard(w http.ResponseWriter, r *http.Request, username, sitePrefix, action string) {
	type Response struct {
		Error string `json:"error,omitempty"`
		Count string `json:"count"`
	}
	// TODO: consider making this writeResponse instead, together with a
	// Response struct that makes sense when called for cut | copy | clear |
	// paste. It also means we can set stuff like InvalidSrcParent |
	// InvalidDestParent for the Error field.
	redirect := func(w http.ResponseWriter, r *http.Request) {
		referer := r.Referer()
		if referer == "" {
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
			return
		}
		http.Redirect(w, r, referer, http.StatusFound)
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
	if r.Method != "POST" {
		methodNotAllowed(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
	err := r.ParseForm()
	if err != nil {
		badRequest(w, r, err)
		return
	}
	switch action {
	case "cut", "copy":
		parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if !isValidParent(parent) {
			redirect(w, r)
			return
		}
		names := r.Form["name"]
		if len(names) == 0 {
			redirect(w, r)
			return
		}
		clipboard := make(url.Values)
		if action == "cut" {
			clipboard.Set("cut", "")
		}
		clipboard.Set("sitePrefix", sitePrefix)
		clipboard.Set("parent", parent)
		clipboard["name"] = names
		http.SetCookie(w, &http.Cookie{
			Path:     "/",
			Name:     "clipboard",
			Value:    clipboard.Encode(),
			MaxAge:   int(time.Hour.Seconds()),
			Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
			HttpOnly: true,
		})
		redirect(w, r)
	case "clear":
		http.SetCookie(w, &http.Cookie{
			Path:     "/",
			Name:     "clipboard",
			Value:    "0",
			MaxAge:   -1,
			Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
			HttpOnly: true,
		})
		redirect(w, r)
	case "paste":
		http.SetCookie(w, &http.Cookie{
			Path:     "/",
			Name:     "clipboard",
			Value:    "0",
			MaxAge:   -1,
			Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
			HttpOnly: true,
		})
		cookie, _ := r.Cookie("clipboard")
		if cookie == nil {
			redirect(w, r)
			return
		}
		clipboard, err := url.ParseQuery(cookie.Value)
		if err != nil {
			redirect(w, r)
			return
		}
		srcSitePrefix := clipboard.Get("sitePrefix")
		if srcSitePrefix != "" && !strings.HasPrefix(srcSitePrefix, "@") && !strings.Contains(srcSitePrefix, ".") {
			redirect(w, r)
			return
		}
		srcParent := path.Clean(strings.Trim(clipboard.Get("parent"), "/"))
		if !isValidParent(srcParent) {
			redirect(w, r)
			return
		}
		destParent := path.Clean(strings.Trim(r.Form.Get("destination"), "/"))
		if !isValidParent(destParent) {
			redirect(w, r)
			return
		}
		seen := make(map[string]bool)
		isCut := clipboard.Has("cut")
		g, ctx := errgroup.WithContext(r.Context())
		for _, name := range clipboard["name"] {
			name := name
			if seen[name] {
				continue
			}
			g.Go(func() error {
				remoteFS, ok := nbrew.FS.(*RemoteFS)
				if !ok {
					return nil
				}
				_ = remoteFS
				_ = ctx
				_ = isCut
				return nil
			})
		}
		err = g.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		redirect(w, r)
	default:
		notFound(w, r)
	}
}

type pasteCandidate struct {
	SrcFilePath  string
	SrcIsDir     bool
	DestFilePath string
	DestIsDir    bool
}

func remotePasteFile(ctx context.Context, fsys FS, candidates []pasteCandidate) error {
	g, ctx := errgroup.WithContext(ctx)
	_ = g
	for _, candidate := range candidates {
		if candidate.SrcFilePath == "" {
			continue
		}
		if !candidate.SrcIsDir {
			if candidate.DestFilePath == "" {
				// move the file; if file is pages/* or posts/*, move the outputDir over as well
			} else {
				// replace the file; if the file is pages/* or posts/*, delete the oldputDir and move over the new one.
			}
		}
	}
	return nil
}

func moveFile(ctx context.Context, fsys FS, destPath, srcPath, name string) error {
	if remoteFS, ok := fsys.(*RemoteFS); ok {
		_ = remoteFS
	}
	//
	err := fsys.WithContext(ctx).Rename(path.Join(srcPath, name), path.Join(destPath, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if errors.Is(err, syscall.EISDIR) {
			err := fsys.WithContext(ctx).RemoveAll(path.Join(destPath, name))
			if err != nil {
				return err
			}
			err = fsys.WithContext(ctx).Rename(path.Join(srcPath, name), path.Join(destPath, name))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func copyFile(ctx context.Context, fsys FS, destPath, srcPath, name string) error {
	return nil
}
