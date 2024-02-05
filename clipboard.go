package nb9

import (
	"context"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) clipboard(w http.ResponseWriter, r *http.Request, username, sitePrefix, action string) {
	type Response struct {
		Error     string `json:"error,omitempty"`
		Count     string `json:"count"`
		NumPasted int    `json:"numPasted,omitempty"`
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
		parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if !isValidParent(parent) {
			redirect(w, r)
			return
		}
		// 1. Grab all the names that exist in the parent destination, put it in a map.
		// 2. Iterate the name list and if it's determined to already exist, skip it.
		// 3. For each name
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

func (nbrew *Notebrew) clipboardV2(w http.ResponseWriter, r *http.Request, username, sitePrefix, action string) {
	type Response struct {
		Error     string     `json:"error,omitempty"`
		Count     string     `json:"count"`
		Conflicts []conflict `json:"conflicts"`
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
		parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if !isValidParent(parent) {
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
	SrcExists      bool
	SrcSitePrefix  string
	SrcFilePath    string
	SrcIsDir       bool
	DestExists     bool
	DestSitePrefix string
	DestFilePath   string
	DestIsDir      bool
}

type conflict struct {
	SrcParent    string
	DestParent   string
	Name         string
	ConflictType string // DestExists | FileReplacesDir | DirReplacesFile | HTMLOnly | MarkdownOnly
	Overwrite    bool   // only application if conflictType == DestExists
}

// resolution map[conflict]bool

type resolution struct {
	srcParent  string
	destParent string
	name       string
	overwrite  bool
}

func remotePasteFileV2(ctx context.Context, remoteFS *RemoteFS, srcSitePrefix, srcParent, destSitePrefix, destParent string, names []string) error {
	// loop the dir
	return nil
}

// srcParent destParent name
func remotePasteFile(ctx context.Context, remoteFS *RemoteFS, candidates []pasteCandidate) error {
	g, ctx := errgroup.WithContext(ctx)
	_ = g
	// TODO: come up with a better name than "candidate" cos it's so freaking
	// long.
	// resolution { srcParent; destParent; name; overwrite bool }
	for _, c := range candidates {
		if !c.SrcExists {
			continue
		}
		srcHead, _, _ := strings.Cut(c.SrcFilePath, "/")
		destHead, _, _ := strings.Cut(c.DestFilePath, "/")
		if c.DestExists && !c.DestIsDir {
			// TODO: remove the dest outputDir
			if destHead == "pages" && strings.HasSuffix(c.DestFilePath, ".html") {
			} else if destHead == "posts" && strings.HasSuffix(c.DestFilePath, ".md") {
			}
		}
		if !c.SrcIsDir {
			if !c.DestExists {
				// TODO: move the file
			} else {
				// TODO: replace the file
			}
			if srcHead == "pages" || srcHead == "posts" {
				// TODO: move the src outputDir
			}
		} else {
			if !c.DestExists {
				// TODO: move the folder
			} else if false {
			}
		}
		// INSERT ON CONFLICT DO UPDATE
	}
	return nil
}
