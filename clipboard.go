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
		type Response struct {
			Error        string   `json:"error,omitempty"`
			IsCut        bool     `json:"isCut,omitempty"`
			CopyOnly     bool     `json:"copyOnly,omitempty"`
			NumPasted    int      `json:"numPasted,omitempty"`
			FilesExist   []string `json:"filesExist,omitempty"`
			FilesInvalid []string `json:"filesInvalid,omitempty"`
			// NOTE:
			// pasted $x files (copied instead of moved)
			// the following files already exist:
			// the following files are non-markdown files or contain non-markdown files:
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
			if response.Error != "" {
				http.Redirect(w, r, referer, http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":           "clipboard/paste",
					"copiedNotMoved": response.CopyOnly,
					"numPasted":      response.NumPasted,
					"filesExist":     response.FilesExist,
					"filesInvalid":   response.FilesInvalid,
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
		var response Response
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
		names := clipboard["name"]
		slices.Sort(names)
		names = slices.Compact(names)
		srcSitePrefix := clipboard.Get("sitePrefix")
		if srcSitePrefix != "" && !strings.HasPrefix(srcSitePrefix, "@") && !strings.Contains(srcSitePrefix, ".") {
			response.Error = "InvalidSrcSitePrefix"
			writeResponse(w, r, response)
			return
		}
		srcParent := path.Clean(strings.Trim(clipboard.Get("parent"), "/"))
		if !isValidParent(srcParent) {
			response.Error = "InvalidSrcParent"
			writeResponse(w, r, response)
			return
		}
		parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if !isValidParent(parent) {
			response.Error = "InvalidDestParent"
			writeResponse(w, r, response)
			return
		}
		srcHead, srcTail, _ := strings.Cut(srcParent, "/")
		destHead, destTail, _ := strings.Cut(parent, "/")
		response.IsCut = clipboard.Has("cut")
		response.CopyOnly = (srcHead == "pages" && destHead != "pages") || (srcHead == "posts" && destHead != "posts")

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

		// stat srcFile; if not exist, return
		// stat destFile; if exist, append to FilesExist and return
		// if destHead is pages,
		//   if srcFile is a file and does not end in .html, append to FilesInvalid and return
		//   if srcFile is a folder and contains a non .html file, append to FilesInvalid and return
		// if destHead is posts,
		//   if srcFile is a file and does not end in .md, append to FilesInvalid and return
		//   if srcFile is a folder and contains a non .md file, append to FilesInvalid and return
		// if isCut
		//   if nbrew.FS is remoteFS, reparent the srcFile by changing its parentID and filePath then batch rename all its descendents (follow Rename() in fs_remote.go). Do the same for the file's outputDir if destHead is pages or posts
		//   else rename the srcFile to the destFile. Do the same for the file's outputDir if destHead is pages or posts
		// else
		//   if nbrew.FS is remoteFS, insert a new destFile entry using INSERT ... SELECT from the srcFile, changing only the file_id, parent_id, mod_time and creation_time.
		//   else walkdir the srcFile, copying a directory or copying a file when necessary. as an optimization we can actually walk twice, first synchronously to copy the directories. Then copy all files asynchronously using an errgroup.
		errInvalid := fmt.Errorf("file is invalid or contains invalid files")
		group, ctx := errgroup.WithContext(r.Context())
		for _, name := range names {
			name := name
			group.Go(func() error {
				srcFilePath := path.Join(srcSitePrefix, srcParent, name)
				srcFileInfo, err := fs.Stat(nbrew.FS.WithContext(ctx), srcFilePath)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
				}
				destFilePath := path.Join(sitePrefix, parent, name)
				_, err = fs.Stat(nbrew.FS.WithContext(ctx), destFilePath)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return err
					}
				} else {
					existCh <- destFilePath
					return nil
				}
				var srcOutputDir, destOutputDir string
				switch srcHead {
				case "pages":
					if !srcFileInfo.IsDir() {
						srcOutputDir = path.Join(srcSitePrefix, "output", srcTail, strings.TrimSuffix(name, ".html"))
						if destHead == "pages" {
							destOutputDir = path.Join(sitePrefix, "output", destTail, strings.TrimSuffix(name, ".html"))
						}
						if !strings.HasSuffix(srcFilePath, ".html") {
							invalidCh <- srcFilePath
							return nil
						}
					} else {
						srcOutputDir = path.Join(srcSitePrefix, "output", srcTail, name)
						if destHead == "pages" {
							destOutputDir = path.Join(sitePrefix, "output", destTail, name)
						}
						if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
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
							err := fs.WalkDir(nbrew.FS.WithContext(ctx), srcFilePath, func(filePath string, dirEntry fs.DirEntry, err error) error {
								if err != nil {
									return err
								}
								if !dirEntry.IsDir() && !strings.HasSuffix(filePath, ".html") {
									return errInvalid
								}
								return nil
							})
							if err != nil {
								if errors.Is(err, errInvalid) {
									invalidCh <- srcFilePath
									return nil
								}
								return err
							}
						}
					}
				case "posts":
					if !srcFileInfo.IsDir() {
						srcOutputDir = path.Join(srcSitePrefix, "output/posts", srcTail, strings.TrimSuffix(name, ".md"))
						if destHead == "posts" {
							destOutputDir = path.Join(sitePrefix, "output/posts", destTail, strings.TrimSuffix(name, ".md"))
						}
						if !strings.HasSuffix(srcFilePath, ".md") {
							invalidCh <- srcFilePath
							return nil
						}
					} else {
						srcOutputDir = path.Join(srcSitePrefix, "output/posts", srcTail, name)
						if destHead == "posts" {
							destOutputDir = path.Join(sitePrefix, "output/posts", destTail, name)
						}
						if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
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
							err := fs.WalkDir(nbrew.FS.WithContext(ctx), srcFilePath, func(filePath string, dirEntry fs.DirEntry, err error) error {
								if err != nil {
									return err
								}
								if !dirEntry.IsDir() && !strings.HasSuffix(filePath, ".md") {
									return errInvalid
								}
								return nil
							})
							if err != nil {
								if errors.Is(err, errInvalid) {
									invalidCh <- srcFilePath
									return nil
								}
								return err
							}
						}
					}
				}
				if response.IsCut && !response.CopyOnly {
					err := nbrew.FS.WithContext(ctx).Rename(srcFilePath, destFilePath)
					if err != nil {
						return err
					}
					if srcOutputDir != "" && destOutputDir != "" {
						err := nbrew.FS.WithContext(ctx).Rename(srcOutputDir, destOutputDir)
						if err != nil {
							return err
						}
					}
					return nil
				}
				if !srcFileInfo.IsDir() {
					if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
					}
				}
				if !srcFileInfo.IsDir() {
					srcFile, err := nbrew.FS.WithContext(ctx).Open(srcFilePath)
					if err != nil {
						return err
					}
					defer srcFile.Close()
					destFile, err := nbrew.FS.WithContext(ctx).OpenWriter(destFilePath, 0644)
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
				} else {
					subgroupA, subctxA := errgroup.WithContext(ctx)
					err := fs.WalkDir(nbrew.FS.WithContext(subctxA), srcFilePath, func(filePath string, dirEntry fs.DirEntry, err error) error {
						if err != nil {
							return err
						}
						relPath := strings.Trim(strings.TrimSuffix(filePath, srcFilePath), "/")
						if dirEntry.IsDir() {
							err := nbrew.FS.WithContext(subctxA).MkdirAll(path.Join(destFilePath, relPath), 0755)
							if err != nil {
								return err
							}
							return nil
						}
						subgroupA.Go(func() error {
							srcFile, err := nbrew.FS.WithContext(subctxA).Open(filePath)
							if err != nil {
								return err
							}
							defer srcFile.Close()
							destFile, err := nbrew.FS.WithContext(subctxA).OpenWriter(path.Join(destFilePath, relPath), 0644)
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
				if srcOutputDir != "" && destOutputDir != "" {
					g2B, ctx2B := errgroup.WithContext(ctx)
					err := fs.WalkDir(nbrew.FS.WithContext(ctx2B), srcOutputDir, func(filePath string, dirEntry fs.DirEntry, err error) error {
						if err != nil {
							return err
						}
						relPath := strings.Trim(strings.TrimSuffix(filePath, srcOutputDir), "/")
						if dirEntry.IsDir() {
							err := nbrew.FS.WithContext(ctx2B).MkdirAll(path.Join(destOutputDir, relPath), 0755)
							if err != nil {
								return err
							}
							return nil
						}
						g2B.Go(func() error {
							srcFile, err := nbrew.FS.WithContext(ctx2B).Open(filePath)
							if err != nil {
								return err
							}
							defer srcFile.Close()
							destFile, err := nbrew.FS.WithContext(ctx2B).OpenWriter(path.Join(destOutputDir, relPath), 0644)
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
					err = g2B.Wait()
					if err != nil {
						return nil
					}
				}
				return nil
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

func remotePaste(ctx context.Context, remoteFS *RemoteFS) error {
	return nil
}

func move(ctx context.Context, remoteFS *RemoteFS, isCut bool, srcSitePrefix, srcParent, destSitePrefix, destParent string, names []string) error {
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
