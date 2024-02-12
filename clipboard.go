package nb9

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/nb9/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) clipboard(w http.ResponseWriter, r *http.Request, username, sitePrefix, action string) {
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
			// TODO: allow non-themes files (but that means we need to impose
			// additional checks when pasting, such as output/* only allowing
			// image, css, javascript or markdown files and output/posts/* only
			// allowing image files).
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
	referer := r.Referer()
	if referer == "" {
		referer = "/" + path.Join("files", sitePrefix) + "/"
	}
	switch action {
	case "cut", "copy":
		parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if !isValidParent(parent) {
			http.Redirect(w, r, referer, http.StatusFound)
			return
		}
		names := r.Form["name"]
		if len(names) == 0 {
			http.Redirect(w, r, referer, http.StatusFound)
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
		http.Redirect(w, r, referer, http.StatusFound)
	case "clear":
		http.SetCookie(w, &http.Cookie{
			Path:     "/",
			Name:     "clipboard",
			Value:    "0",
			MaxAge:   -1,
			Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
			HttpOnly: true,
		})
		http.Redirect(w, r, referer, http.StatusFound)
	case "paste":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response pasteResponse) {
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
				http.Redirect(w, r, referer, http.StatusFound)
				return
			}
			srcHead, _, _ := strings.Cut(response.SrcParent, "/")
			destHead, _, _ := strings.Cut(response.DestParent, "/")
			// NOTE: copyOnly = (srcHead == "pages" && destHead != "pages") || (srcHead == "posts" && destHead != "posts")
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":         "clipboard/paste",
					"srcHead":      srcHead,
					"destHead":     destHead,
					"isCut":        response.IsCut,
					"numPasted":    response.NumPasted,
					"filesExist":   response.FilesExist,
					"filesInvalid": response.FilesInvalid,
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, referer, http.StatusFound)
		}
		http.SetCookie(w, &http.Cookie{
			Path:     "/",
			Name:     "clipboard",
			Value:    "0",
			MaxAge:   -1,
			Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
			HttpOnly: true,
		})
		var response pasteResponse
		cookie, _ := r.Cookie("clipboard")
		if cookie == nil {
			response.Error = "CookieNotProvided"
			writeResponse(w, r, response)
			return
		}
		clipboard, err := url.ParseQuery(cookie.Value)
		if err != nil {
			response.Error = "InvalidCookieValue"
			writeResponse(w, r, response)
			return
		}
		response.IsCut = clipboard.Has("cut")
		names := clipboard["name"]
		slices.Sort(names)
		names = slices.Compact(names)
		response.SrcSitePrefix = clipboard.Get("sitePrefix")
		if response.SrcSitePrefix != "" && !strings.HasPrefix(response.SrcSitePrefix, "@") && !strings.Contains(response.SrcSitePrefix, ".") {
			response.Error = "InvalidSrcSitePrefix"
			writeResponse(w, r, response)
			return
		}
		response.SrcParent = path.Clean(strings.Trim(clipboard.Get("parent"), "/"))
		if !isValidParent(response.SrcParent) {
			response.Error = "InvalidSrcParent"
			writeResponse(w, r, response)
			return
		}
		response.DestSitePrefix = sitePrefix
		response.DestParent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if !isValidParent(response.DestParent) {
			response.Error = "InvalidDestParent"
			writeResponse(w, r, response)
			return
		}

		var numPasted atomic.Int64
		var wg sync.WaitGroup
		existCh := make(chan string)
		go func() {
			wg.Add(1)
			defer wg.Done()
			for filePath := range existCh {
				response.FilesExist = append(response.FilesExist, filePath)
			}
		}()
		invalidCh := make(chan string)
		go func() {
			wg.Add(1)
			defer wg.Done()
			for filePath := range invalidCh {
				response.FilesInvalid = append(response.FilesInvalid, filePath)
			}
		}()
		group, ctx := errgroup.WithContext(r.Context())
		for _, name := range names {
			name := name
			group.Go(func() error {
				return paste(ctx, nbrew.FS, response, name, &numPasted, existCh, invalidCh)
			})
		}
		err = group.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		response.NumPasted = int(numPasted.Load())
		close(existCh)
		close(invalidCh)
		wg.Wait()
		writeResponse(w, r, response)
	default:
		notFound(w, r)
	}
}

type pasteResponse struct {
	Error          string   `json:"error,omitempty"`
	SrcSitePrefix  string   `json:"srcSitePrefix,omitempty"`
	SrcParent      string   `json:"srcParent,omitempty"`
	DestSitePrefix string   `json:"destSitePrefix,omitempty"`
	DestParent     string   `json:"destParent,omitempty"`
	IsCut          bool     `json:"isCut,omitempty"`
	NumPasted      int      `json:"numPasted,omitempty"`
	FilesExist     []string `json:"filesExist,omitempty"`
	FilesInvalid   []string `json:"filesInvalid,omitempty"`
	// NOTE:
	// pasted $x files (copied instead of moved)
	// the following files already exist:
	// the following files are non-markdown files or contain non-markdown files:
}

var errFileInvalid = fmt.Errorf("file is invalid or is a directory containing invalid files")

// stat srcFile; if not exist, return
// stat destFile; if exist, append to FilesExist and return
// if destHead is pages,
//
//	if srcFile is a file and does not end in .html, append to FilesInvalid and return
//	if srcFile is a folder and contains a non .html file, append to FilesInvalid and return
//
// if destHead is posts,
//
//	if srcFile is a file and does not end in .md, append to FilesInvalid and return
//	if srcFile is a folder and contains a non .md file, append to FilesInvalid and return
//
// if isCut
//
//	if nbrew.FS is remoteFS, reparent the srcFile by changing its parentID and filePath then batch rename all its descendents (follow Rename() in fs_remote.go). Do the same for the file's outputDir if destHead is pages or posts
//	else rename the srcFile to the destFile. Do the same for the file's outputDir if destHead is pages or posts
//
// else
//
//	if nbrew.FS is remoteFS, insert a new destFile entry using INSERT ... SELECT from the srcFile, changing only the file_id, parent_id, mod_time and creation_time.
//	else walkdir the srcFile, copying a directory or copying a file when necessary. as an optimization we can actually walk twice, first synchronously to copy the directories. Then copy all files asynchronously using an errgroup.
//
// NOTE: isMove := response.IsCut && !response.CopyOnly
func paste(ctx context.Context, fsys FS, response pasteResponse, name string, numPasted *atomic.Int64, existCh, invalidCh chan<- string) error {
	srcHead, srcTail, _ := strings.Cut(response.SrcParent, "/")
	srcFilePath := path.Join(response.SrcSitePrefix, response.SrcParent, name)
	srcFileInfo, err := fs.Stat(fsys.WithContext(ctx), srcFilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	destHead, destTail, _ := strings.Cut(response.DestParent, "/")
	destFilePath := path.Join(response.DestSitePrefix, response.DestParent, name)
	_, err = fs.Stat(fsys.WithContext(ctx), destFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else {
		existCh <- destFilePath
		return nil
	}
	var srcOutputDir string
	switch srcHead {
	case "pages":
		if !srcFileInfo.IsDir() {
			srcOutputDir = path.Join(response.SrcSitePrefix, "output", srcTail, strings.TrimSuffix(name, ".html"))
		} else {
			srcOutputDir = path.Join(response.SrcSitePrefix, "output", srcTail, name)
		}
	case "posts":
		if !srcFileInfo.IsDir() {
			srcOutputDir = path.Join(response.SrcSitePrefix, "output/posts", srcTail, strings.TrimSuffix(name, ".md"))
		} else {
			srcOutputDir = path.Join(response.SrcSitePrefix, "output/posts", srcTail, name)
		}
	}
	var destOutputDir string
	switch destHead {
	case "pages":
		if !srcFileInfo.IsDir() {
			destOutputDir = path.Join(response.DestSitePrefix, "output", destTail, strings.TrimSuffix(name, ".html"))
			if !strings.HasSuffix(srcFilePath, ".html") {
				invalidCh <- srcFilePath
				return nil
			}
		} else {
			destOutputDir = path.Join(response.DestSitePrefix, "output", destTail, name)
			if remoteFS, ok := fsys.(*RemoteFS); ok {
				exists, err := sq.FetchExists(ctx, remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format:  "SELECT 1 FROM files WHERE file_path LIKE {pattern} AND NOT is_dir AND file_path NOT LIKE '%.html'",
					Values: []any{
						sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(srcFilePath)+"/%"),
					},
				})
				if err != nil {
					return err
				}
				if exists {
					invalidCh <- srcFilePath
					return nil
				}
			} else {
				err := fs.WalkDir(fsys.WithContext(ctx), srcFilePath, func(filePath string, dirEntry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if !dirEntry.IsDir() && !strings.HasSuffix(filePath, ".html") {
						return errFileInvalid
					}
					return nil
				})
				if err != nil {
					if errors.Is(err, errFileInvalid) {
						invalidCh <- srcFilePath
						return nil
					}
					return err
				}
			}
		}
	case "posts":
		if !srcFileInfo.IsDir() {
			destOutputDir = path.Join(response.DestSitePrefix, "output/posts", destTail, strings.TrimSuffix(name, ".md"))
			if !strings.HasSuffix(srcFilePath, ".md") {
				invalidCh <- srcFilePath
				return nil
			}
		} else {
			destOutputDir = path.Join(response.DestSitePrefix, "output/posts", destTail, name)
			if remoteFS, ok := fsys.(*RemoteFS); ok {
				exists, err := sq.FetchExists(ctx, remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format:  "SELECT 1 FROM files WHERE file_path LIKE {pattern} AND NOT is_dir AND file_path NOT LIKE '%.md'",
					Values: []any{
						sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(srcFilePath)+"/%"),
					},
				})
				if err != nil {
					return err
				}
				if exists {
					invalidCh <- srcFilePath
					return nil
				}
			} else {
				err := fs.WalkDir(fsys.WithContext(ctx), srcFilePath, func(filePath string, dirEntry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if !dirEntry.IsDir() && !strings.HasSuffix(filePath, ".md") {
						return errFileInvalid
					}
					return nil
				})
				if err != nil {
					if errors.Is(err, errFileInvalid) {
						invalidCh <- srcFilePath
						return nil
					}
					return err
				}
			}
		}
	case "output":
		next, _, _ := strings.Cut(srcTail, "/")
		if next == "posts" {
			// TODO: check that srcFilePath only contains images files
		} else if next != "themes" {
			// TODO: check that srcFilePath only contains images, css, javascript or markdown files
		}
	}
	numPasted.Add(1)
	moveNotAllowed := (srcHead == "pages" && destHead != "pages") || (srcHead == "posts" && destHead != "posts")
	if response.IsCut && !moveNotAllowed {
		err := fsys.WithContext(ctx).Rename(srcFilePath, destFilePath)
		if err != nil {
			return err
		}
		if srcOutputDir != "" && destOutputDir != "" {
			err := fsys.WithContext(ctx).Rename(srcOutputDir, destOutputDir)
			if err != nil {
				return err
			}
		}
		return nil
	}
	if !srcFileInfo.IsDir() {
		if remoteFS, ok := fsys.(*RemoteFS); ok {
			srcFileID := srcFileInfo.(*RemoteFileInfo).FileID
			destFileID := NewID()
			modTime := time.Now().UTC()
			_, err := sq.Exec(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
					" SELECT {destFileID}, (SELECT file_id FROM files WHERE file_path = {destParent}), {destFilePath}, {modTime}, {modTime}, is_dir, size, text, data" +
					" FROM files" +
					" WHERE file_path = {srcFilePath}",
				Values: []any{
					sq.UUIDParam("destFileID", destFileID),
					sq.StringParam("destParent", path.Dir(destFilePath)),
					sq.StringParam("destFilePath", destFilePath),
					sq.Param("modTime", sq.Timestamp{Time: modTime, Valid: true}),
					sq.StringParam("srcFilePath", srcFilePath),
				},
			})
			if err != nil {
				return err
			}
			ext := path.Ext(srcFilePath)
			fileType := fileTypes[ext]
			if fileType.IsObject {
				err := remoteFS.storage.Copy(ctx, hex.EncodeToString(srcFileID[:])+ext, hex.EncodeToString(destFileID[:])+ext)
				if err != nil {
					getLogger(ctx).Error(err.Error())
				}
			}
		} else {
			srcFile, err := fsys.WithContext(ctx).Open(srcFilePath)
			if err != nil {
				return err
			}
			defer srcFile.Close()
			destFile, err := fsys.WithContext(ctx).OpenWriter(destFilePath, 0644)
			if err != nil {
				return err
			}
			defer destFile.Close()
			_, err = io.Copy(destFile, srcFile)
			if err != nil {
				return err
			}
			err = destFile.Close()
			if err != nil {
				return err
			}
		}
	} else {
		if remoteFS, ok := fsys.(*RemoteFS); ok {
			// TODO: batch insert using a JOIN with a json blob containing
			// destFileID, destParent, destFilePath and modTime (the rest can
			// be pulled from the files table itself). We'll have to query the
			// table first to obtain all the filePaths, then generate a fileID
			// for each filePath to build the JSON (potentially very big if
			// many nested children !!). Then submit the serialized json blob
			// to the database, do a join on it and insert. On destFileID
			// generation, we can also do a copyObject as well (which means we
			// definitely do have to fetch the srcFileIDs at the same time, as
			// well as the filePath).
			//
			// We need to order the results by file_path, so that we always see
			// the folders first before the files inside. Then we can store
			// parent fileIDs in a map as we generate them, and use
			// path.Dir(filePath) to consult the map for the correct parentID
			// to put inside the json row.
			_ = remoteFS
		} else {
			subgroupA, subctxA := errgroup.WithContext(ctx)
			err := fs.WalkDir(fsys.WithContext(subctxA), srcFilePath, func(filePath string, dirEntry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				relPath := strings.Trim(strings.TrimSuffix(filePath, srcFilePath), "/")
				if dirEntry.IsDir() {
					err := fsys.WithContext(subctxA).MkdirAll(path.Join(destFilePath, relPath), 0755)
					if err != nil {
						return err
					}
					return nil
				}
				subgroupA.Go(func() error {
					srcFile, err := fsys.WithContext(subctxA).Open(filePath)
					if err != nil {
						return err
					}
					defer srcFile.Close()
					destFile, err := fsys.WithContext(subctxA).OpenWriter(path.Join(destFilePath, relPath), 0644)
					if err != nil {
						return err
					}
					defer destFile.Close()
					_, err = io.Copy(destFile, srcFile)
					if err != nil {
						return err
					}
					err = destFile.Close()
					if err != nil {
						return err
					}
					return nil
				})
				return nil
			})
			if err != nil {
				return nil
			}
			err = subgroupA.Wait()
			if err != nil {
				return nil
			}
		}
	}
	if srcOutputDir != "" && destOutputDir != "" {
		subgroupB, subctxB := errgroup.WithContext(ctx)
		err := fs.WalkDir(fsys.WithContext(subctxB), srcOutputDir, func(filePath string, dirEntry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relPath := strings.Trim(strings.TrimSuffix(filePath, srcOutputDir), "/")
			if dirEntry.IsDir() {
				err := fsys.WithContext(subctxB).MkdirAll(path.Join(destOutputDir, relPath), 0755)
				if err != nil {
					return err
				}
				return nil
			}
			subgroupB.Go(func() error {
				srcFile, err := fsys.WithContext(subctxB).Open(filePath)
				if err != nil {
					return err
				}
				defer srcFile.Close()
				destFile, err := fsys.WithContext(subctxB).OpenWriter(path.Join(destOutputDir, relPath), 0644)
				if err != nil {
					return err
				}
				defer destFile.Close()
				_, err = io.Copy(destFile, srcFile)
				if err != nil {
					return err
				}
				err = destFile.Close()
				if err != nil {
					return err
				}
				return nil
			})
			return nil
		})
		if err != nil {
			return nil
		}
		err = subgroupB.Wait()
		if err != nil {
			return nil
		}
	}
	return nil
}

func remotePaste_Old(ctx context.Context, remoteFS *RemoteFS, isCut bool, srcSitePrefix, srcParent, destSitePrefix, destParent string, names []string) error {
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
					Result:  sq.Expr("SELECT 1 FROM json_table({}, COLUMNS (value VARCHAR(500) PATH '$')) AS dest_paths WHERE dest_paths.value = files.file_path", b.String()),
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
