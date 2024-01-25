package nb9

import (
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) clipboard(w http.ResponseWriter, r *http.Request, username, sitePrefix, action string) {
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
		parent := path.Clean(strings.Trim(clipboard.Get("parent"), "/"))
		if !isValidParent(parent) {
			redirect(w, r)
			return
		}
		destination := path.Clean(strings.Trim(r.Form.Get("destination"), "/"))
		if !isValidParent(destination) {
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
				srcFileInfo, err := fs.Stat(nbrew.FS.WithContext(ctx), path.Join(srcSitePrefix, parent, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
				}
				var destNotExist bool
				destFileInfo, err := fs.Stat(nbrew.FS.WithContext(ctx), path.Join(sitePrefix, destination, name))
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return err
					}
					destNotExist = true
				}
				if srcFileInfo.IsDir() {
					if destNotExist {
						if isCut {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						} else {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						}
					} else if destFileInfo.IsDir() {
						if isCut {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						} else {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						}
					} else {
						if isCut {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						} else {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						}
					}
				} else {
					if destNotExist {
						if isCut {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						} else {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						}
					} else if destFileInfo.IsDir() {
						if isCut {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						} else {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						}
					} else {
						if isCut {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						} else {
							if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
								_ = remoteFS
							} else {
							}
						}
					}
				}
				return nil
			})
		}
		err = g.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
	default:
		notFound(w, r)
	}
}

// srcfilename destfilename (make sure to sanitize the destfilename's sitePrefix)
func paste() {
}
