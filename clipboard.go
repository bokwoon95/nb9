package nb9

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/bokwoon95/nb9/sq"
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
		names := clipboard["name"]
		slices.Sort(names)
		names = slices.Compact(names)
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
		if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
			err := remotePaste(r.Context(), remoteFS, clipboard.Has("cut"), srcSitePrefix, srcParent, sitePrefix, parent, names)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		// 1. Grab all the names that exist in the parent destination, put it in a map.
		// 2. Iterate the name list and if it's determined to already exist, skip it.
		// 3a. If it's cut, do an UPDATE ... JOIN json_table({names})
		// 3b. If it's copy, do an INSERT ... SELECT ... FROM files JOIN json_table({names})
		// ["6409929d-442e-4ac3-a675-a07b41368133", "posts/python/libs.md"]
		// filedata = append(filedata, []string{"", ""})
		// list
		// {blob}
		redirect(w, r)
	default:
		notFound(w, r)
	}
}

func move(ctx context.Context, remoteFS *RemoteFS, isCut bool, srcSitePrefix, srcParent, destSitePrefix, destParent string, names []string) error {
	return nil
}

func remotePaste(ctx context.Context, remoteFS *RemoteFS, isCut bool, srcSitePrefix, srcParent, destSitePrefix, destParent string, names []string) error {
	destPaths := make([]string, 0, len(names))
	for _, name := range names {
		destPaths = append(destPaths, path.Join(destSitePrefix, destParent, name))
	}
	var b strings.Builder
	encoder := json.NewEncoder(&b)
	err := encoder.Encode(destPaths)
	if err != nil {
		return err
	}
	cursor, err := sq.FetchCursor(ctx, remoteFS.filesDB, sq.Query{
		Dialect: remoteFS.filesDialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {destParent})" +
			" AND EXISTS ({inDestPaths})",
		Values: []any{
			sq.StringParam("destParent", path.Join(destSitePrefix, destParent)),
			sq.Param("inDestPaths", sq.DialectExpression{
				Default: sq.Expr("SELECT 1 FROM json_each({}) AS dest_paths WHERE dest_paths.value = files.file_path", b.String()),
				Cases: []sq.DialectCase{{
					Dialect: "postgres",
					Result:  sq.Expr("SELECT 1 FROM json_array_elements_text({}) AS dest_paths WHERE dest_paths.value = files.file_path", b.String()),
				}, {
					Dialect: "mysql",
					Result:  sq.Expr("SELECT 1 FROM json_table({}, COLUMNS (value VARCHAR(500) path '$')) AS dest_paths WHERE dest_paths.value = files.file_path", b.String()),
				}},
			}),
		},
	}, func(row *sq.Row) string {
		return path.Base(row.String("files.file_path"))
	})
	if err != nil {
		return err
	}
	defer cursor.Close()
	nameAlreadyExists := make(map[string]struct{})
	for cursor.Next() {
		name, err := cursor.Result()
		if err != nil {
			return err
		}
		nameAlreadyExists[name] = struct{}{}
	}
	err = cursor.Close()
	if err != nil {
		return err
	}
	if len(nameAlreadyExists) > 0 {
		n := 0
		for _, name := range names {
			if _, ok := nameAlreadyExists[name]; ok {
				continue
			}
			names[n] = name
			n++
		}
		names = names[:n]
	}
	if isCut {
		srcPaths := make([]string, 0, len(names))
		for _, name := range names {
			srcPaths = append(srcPaths, path.Join(srcSitePrefix, srcParent, name))
		}
		var b strings.Builder
		encoder := json.NewEncoder(&b)
		err := encoder.Encode(srcPaths)
		if err != nil {
			return err
		}
		switch remoteFS.filesDialect {
		case "sqlite":
			_, err := sq.Exec(ctx, remoteFS.filesDB, sq.Query{
				Dialect: "sqlite",
				Format: "UPDATE files" +
					" SET file_path = {destParent} || substring(file_path, {start})" +
					", mod_time = {modTime}" +
					" FROM json_table({srcPaths}) AS src_paths" +
					" WHERE src_paths.value = files.file_path",
				Values: []any{
					sq.StringParam("destParent", path.Join(destSitePrefix, destParent)),
					sq.IntParam("start", len(path.Join(srcSitePrefix, srcParent))+1),
					sq.TimeParam("modTime", time.Now().UTC()),
					sq.StringParam("srcPaths", b.String()),
				},
			})
			if err != nil {
				return err
			}
		case "postgres":
			_, err := sq.Exec(ctx, remoteFS.filesDB, sq.Query{
				Dialect: "postgres",
				Format: "UPDATE files" +
					" SET file_path = {destParent} || substring(file_path, {start})" +
					", mod_time = {modTime}" +
					" FROM json_array_elements_text({srcPaths}) AS src_paths" +
					" WHERE src_paths.value = files.file_path",
				Values: []any{
					sq.StringParam("destParent", path.Join(destSitePrefix, destParent)),
					sq.IntParam("start", len(path.Join(srcSitePrefix, srcParent))+1),
					sq.TimeParam("modTime", time.Now().UTC()),
					sq.StringParam("srcPaths", b.String()),
				},
			})
			if err != nil {
				return err
			}
		case "mysql":
			_, err := sq.Exec(ctx, remoteFS.filesDB, sq.Query{
				Dialect: "postgres",
				Format: "UPDATE files" +
					" JOIN json_table({srcPaths}, '$[*]' COLUMNS (value VARCHAR(500) PATH '$')) AS src_paths ON src_paths.value = files.file_path" +
					" SET file_path = concat({destParent}, substring(file_path, {start}))" +
					", mod_time = {modTime}",
				Values: []any{
					sq.StringParam("destParent", path.Join(destSitePrefix, destParent)),
					sq.IntParam("start", len(path.Join(srcSitePrefix, srcParent))+1),
					sq.TimeParam("modTime", time.Now().UTC()),
					sq.StringParam("srcPaths", b.String()),
				},
			})
			if err != nil {
				return err
			}
		default:
			return nil
		}
		// srcHead, _, _ := strings.Cut(srcParent, "/")
		// if srcHead == "pages" {
		// 	srcOutput := path.Join(srcSitePrefix, "output", srcParent)
		// }
		// if destHead == "pages" {
		// 	srcOutput := path.Join(destSitePrefix)
		// }
		// if destParent one of pages/* | posts/*, delete the old stuff
		// for name, delete
	} else {
		newFiles := make([][2]string, 0, len(names))
		for _, name := range names {
			var buf [32 + 4]byte
			id := NewID()
			hex.Encode(buf[:], id[:4])
			buf[8] = '-'
			hex.Encode(buf[9:13], id[4:6])
			buf[13] = '-'
			hex.Encode(buf[14:18], id[6:8])
			buf[18] = '-'
			hex.Encode(buf[19:23], id[8:10])
			buf[23] = '-'
			hex.Encode(buf[24:], id[10:])
			newFiles = append(newFiles, [2]string{string(buf[:]), path.Join(srcSitePrefix, srcParent, name)})
		}
		var b strings.Builder
		encoder := json.NewEncoder(&b)
		err := encoder.Encode(newFiles)
		if err != nil {
			return err
		}
	}
	return nil
}
