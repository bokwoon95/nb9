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
		type Response struct {
			Error          string   `json:"error,omitempty"`
			IsCut          bool     `json:"isCut,omitempty"`
			SrcSitePrefix  string   `json:"srcSitePrefix,omitempty"`
			SrcParent      string   `json:"srcParent,omitempty"`
			DestSitePrefix string   `json:"destSitePrefix,omitempty"`
			DestParent     string   `json:"destParent,omitempty"`
			FilesNotExist  []string `json:"filesNotExist,omitempty"`
			FilesExist     []string `json:"filesExist,omitempty"`
			FilesInvalid   []string `json:"filesInvalid,omitempty"`
			FilesPasted    []string `json:"filesPasted,omitmepty"`
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
			srcHead, _, _ := strings.Cut(response.SrcParent, "/")
			destHead, _, _ := strings.Cut(response.DestParent, "/")
			/* {{ if and
			$isCut
			(or
				(and (eq $srcHead "pages") (ne $destHead "pages"))
				(and (eq $srcHead "posts") (ne $destHead $posts))) }} */
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":          "paste",
					"srcHead":       srcHead,
					"destHead":      destHead,
					"isCut":         response.IsCut,
					"filesNotExist": response.FilesNotExist,
					"filesExist":    response.FilesExist,
					"filesInvalid":  response.FilesInvalid,
					"filesPasted":   response.FilesPasted,
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
		if nbrew.UsersDB != nil {
			exists, err := sq.FetchExists(r.Context(), nbrew.UsersDB, sq.Query{
				Dialect: nbrew.UsersDialect,
				Format: "SELECT 1" +
					" FROM site" +
					" JOIN site_user ON site_user.site_id = site.site_id" +
					" JOIN users ON users.user_id = site_user.user_id" +
					" WHERE site.site_name = {siteName}" +
					" AND users.username = {username}",
				Values: []any{
					sq.StringParam("siteName", strings.TrimPrefix(response.SrcSitePrefix, "@")),
					sq.StringParam("username", username),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			if !exists {
				notAuthorized(w, r)
				return
			}
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

		notExistCh := make(chan string)
		go func() {
			for name := range notExistCh {
				response.FilesNotExist = append(response.FilesNotExist, name)
			}
		}()
		existCh := make(chan string)
		go func() {
			for name := range existCh {
				response.FilesExist = append(response.FilesExist, name)
			}
		}()
		invalidCh := make(chan string)
		go func() {
			for name := range invalidCh {
				response.FilesInvalid = append(response.FilesInvalid, name)
			}
		}()
		pastedCh := make(chan string)
		go func() {
			for name := range pastedCh {
				response.FilesPasted = append(response.FilesPasted, name)
			}
		}()
		srcHead, srcTail, _ := strings.Cut(response.SrcParent, "/")
		destHead, destTail, _ := strings.Cut(response.DestParent, "/")
		group, ctx := errgroup.WithContext(r.Context())
		for _, name := range names {
			name := name
			group.Go(func() error {
				err := paste(ctx, nbrew.FS, response.SrcSitePrefix, response.SrcParent, response.DestParent, response.DestSitePrefix, name, response.IsCut)
				if err != nil {
					if errors.Is(err, errNotExist) {
						notExistCh <- name
						return nil
					}
					if errors.Is(err, errExist) {
						existCh <- name
						return nil
					}
					if errors.Is(err, errInvalid) {
						invalidCh <- name
						return nil
					}
					return err
				}
				pastedCh <- name
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
	default:
		notFound(w, r)
	}
}

var (
	errNotExist = fmt.Errorf("src file does not exist")
	errExist    = fmt.Errorf("dest file already exists")
	errInvalid  = fmt.Errorf("src file is invalid or is a directory containing files that are invalid")
)

func paste(ctx context.Context, fsys FS, srcSitePrefix, srcParent, destSitePrefix, destParent, name string, isCut bool) error {
	srcHead, srcTail, _ := strings.Cut(srcParent, "/")
	srcFilePath := path.Join(srcSitePrefix, srcParent, name)
	srcFileInfo, err := fs.Stat(fsys.WithContext(ctx), srcFilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errNotExist
		}
		return err
	}
	destHead, destTail, _ := strings.Cut(destParent, "/")
	destFilePath := path.Join(destSitePrefix, destParent, name)
	_, err = fs.Stat(fsys.WithContext(ctx), destFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else {
		return errExist
	}
	var srcOutputDir string
	switch srcHead {
	case "pages":
		if !srcFileInfo.IsDir() {
			srcOutputDir = path.Join(srcSitePrefix, "output", srcTail, strings.TrimSuffix(name, ".html"))
		} else {
			srcOutputDir = path.Join(srcSitePrefix, "output", srcTail, name)
		}
	case "posts":
		if !srcFileInfo.IsDir() {
			srcOutputDir = path.Join(srcSitePrefix, "output/posts", srcTail, strings.TrimSuffix(name, ".md"))
		} else {
			srcOutputDir = path.Join(srcSitePrefix, "output/posts", srcTail, name)
		}
	}
	var destOutputDir string
	switch destHead {
	case "pages":
		if !srcFileInfo.IsDir() {
			destOutputDir = path.Join(destSitePrefix, "output", destTail, strings.TrimSuffix(name, ".html"))
			if !strings.HasSuffix(srcFilePath, ".html") {
				return errInvalid
			}
		} else {
			destOutputDir = path.Join(destSitePrefix, "output", destTail, name)
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
					return errInvalid
				}
			} else {
				err := fs.WalkDir(fsys.WithContext(ctx), srcFilePath, func(filePath string, dirEntry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if !dirEntry.IsDir() && !strings.HasSuffix(filePath, ".html") {
						return errInvalid
					}
					return nil
				})
				if err != nil {
					return err
				}
			}
		}
	case "posts":
		if !srcFileInfo.IsDir() {
			destOutputDir = path.Join(destSitePrefix, "output/posts", destTail, strings.TrimSuffix(name, ".md"))
			if !strings.HasSuffix(srcFilePath, ".md") {
				return errInvalid
			}
		} else {
			destOutputDir = path.Join(destSitePrefix, "output/posts", destTail, name)
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
					return errInvalid
				}
			} else {
				err := fs.WalkDir(fsys.WithContext(ctx), srcFilePath, func(filePath string, dirEntry fs.DirEntry, err error) error {
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
						return errInvalid
					}
					return err
				}
			}
		}
	case "output":
		next, _, _ := strings.Cut(destTail, "/")
		if srcFileInfo.IsDir() {
			return errInvalid
		}
		ext := path.Ext(srcFilePath)
		if next == "posts" {
			switch ext {
			case ".jpeg", ".jpg", ".png", ".webp", ".gif":
				break
			default:
				return errInvalid
			}
		} else if next != "themes" {
			switch ext {
			case ".jpeg", ".jpg", ".png", ".webp", ".gif", ".css", ".js", ".md":
				break
			default:
				return errInvalid
			}
		}
	}
	moveNotAllowed := (srcHead == "pages" && destHead != "pages") || (srcHead == "posts" && destHead != "posts")
	if isCut && !moveNotAllowed {
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
	if srcFileInfo.IsDir() {
		err = copyDir(ctx, fsys, srcFilePath, destFilePath)
		if err != nil {
			return err
		}
	} else {
		err := copyFile(ctx, fsys, srcFileInfo, srcFilePath, destFilePath)
		if err != nil {
			return err
		}
	}
	if srcOutputDir != "" && destOutputDir != "" {
		err := copyDir(ctx, fsys, srcOutputDir, destOutputDir)
		if err != nil {
			return err
		}
	}
	return nil
}

func copyFile(ctx context.Context, fsys FS, srcFileInfo fs.FileInfo, srcFilePath, destFilePath string) error {
	if remoteFS, ok := fsys.(*RemoteFS); ok {
		srcFileID := srcFileInfo.(*RemoteFileInfo).FileID
		destFileID := NewID()
		modTime := time.Now().UTC()
		_, err := sq.Exec(ctx, remoteFS.filesDB, sq.Query{
			Dialect: remoteFS.filesDialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
				" SELECT" +
				" {destFileID}" +
				", (SELECT file_id FROM files WHERE file_path = {destParent})" +
				", {destFilePath}" +
				", {modTime}" +
				", {modTime}" +
				", is_dir" +
				", size" +
				", text" +
				", data" +
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
		return nil
	}
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
	return nil
}

func copyDir(ctx context.Context, fsys FS, srcDirPath, destDirPath string) error {
	if remoteFS, ok := fsys.(*RemoteFS); ok {
		cursor, err := sq.FetchCursor(ctx, remoteFS.filesDB, sq.Query{
			Dialect: remoteFS.filesDialect,
			Format:  "SELECT * FROM files WHERE file_path = {srcDirPath} OR file_path LIKE {pattern} ORDER BY file_path",
			Values: []any{
				sq.StringParam("srcDirPath", srcDirPath),
				sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(srcDirPath)+"/%"),
			},
		}, func(row *sq.Row) (srcFile struct {
			FileID   [16]byte
			FilePath string
			IsDir    bool
		}) {
			row.UUID(&srcFile.FileID, "file_id")
			srcFile.FilePath = row.String("file_path")
			srcFile.IsDir = row.Bool("is_dir")
			return srcFile
		})
		if err != nil {
			return err
		}
		defer cursor.Close()
		var wg sync.WaitGroup
		var items [][4]string // destFileID, destParentID, destParent, srcFilePath
		fileIDs := make(map[string][16]byte)
		for cursor.Next() {
			srcFile, err := cursor.Result()
			if err != nil {
				return nil
			}
			destFileID := NewID()
			destFilePath := destDirPath + strings.TrimPrefix(srcFile.FilePath, srcDirPath)
			fileIDs[destFilePath] = destFileID
			var item [4]string
			item[0] = encodeUUID(destFileID)
			destParent := path.Dir(destFilePath)
			if destParentID, ok := fileIDs[destParent]; ok {
				item[1] = encodeUUID(destParentID)
			} else {
				item[2] = destParent
			}
			item[3] = srcFile.FilePath
			items = append(items, item)
			if srcFile.IsDir {
				continue
			}
			ext := path.Ext(srcFile.FilePath)
			fileType := fileTypes[ext]
			if !fileType.IsObject {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := remoteFS.storage.Copy(ctx, hex.EncodeToString(srcFile.FileID[:])+ext, hex.EncodeToString(destFileID[:])+ext)
				if err != nil {
					getLogger(ctx).Error(err.Error())
				}
			}()
		}
		err = cursor.Close()
		if err != nil {
			return err
		}
		var b strings.Builder
		err = json.NewEncoder(&b).Encode(items)
		if err != nil {
			return err
		}
		switch remoteFS.filesDialect {
		case "sqlite":
			_, err := sq.Exec(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
					" SELECT" +
					" unhex(items->>0, '-') AS dest_file_id" +
					", CASE WHEN items->>1 <> '' THEN unhex(items->>1, '-') ELSE (SELECT file_id FROM files WHERE file_path = items->>2) END AS dest_parent_id" +
					", concat({destDirPath}, substring(src_files.file_path, {start})) AS dest_file_path" +
					", {modTime}" +
					", {modTime}" +
					", src_files.size" +
					", src_files.text" +
					", src_files.data" +
					" FROM json_each({items}) AS items" +
					" JOIN files AS src_files ON src_files.file_path = items->>3",
				Values: []any{
					sq.StringParam("destDirPath", destDirPath),
					sq.IntParam("start", len(srcDirPath)+1),
					sq.TimeParam("modTime", time.Now().UTC()),
					sq.StringParam("items", b.String()),
				},
			})
			if err != nil {
				return err
			}
		case "postgres":
			_, err := sq.Exec(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
					" SELECT" +
					" CAST(items->>0 AS UUID) AS dest_file_id" +
					", CASE WHEN items->>1 <> '' THEN CAST(items->>1 AS UUID) ELSE (SELECT file_id FROM files WHERE file_path = items->>2) END AS dest_parent_id" +
					", concat({destDirPath}, substring(src_files.file_path, {start})) AS dest_file_path" +
					", {modTime}" +
					", {modTime}" +
					", src_files.size" +
					", src_files.text" +
					", src_files.data" +
					" FROM json_array_elements({items}) AS items" +
					" JOIN files AS src_files ON src_files.file_path = items->>3",
				Values: []any{
					sq.StringParam("destDirPath", destDirPath),
					sq.IntParam("start", len(srcDirPath)+1),
					sq.TimeParam("modTime", time.Now().UTC()),
					sq.StringParam("items", b.String()),
				},
			})
			if err != nil {
				return err
			}
		case "mysql":
			_, err := sq.Exec(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
					" SELECT" +
					" uuid_to_bin(items.dest_file_id) AS dest_file_id" +
					", CASE WHEN items.dest_parent_id <> '' THEN uuid_to_bin(items.dest_parent_id) ELSE (SELECT file_id FROM files WHERE file_path = items.parent_path) END AS dest_parent_id" +
					", concat({destDirPath}, substring(src_files.file_path, {start})) AS dest_file_path" +
					", {modTime}" +
					", {modTime}" +
					", src_files.size" +
					", src_files.text" +
					", src_files.data" +
					" FROM json_table({items}, '$[*]' COLUMNS (" +
					"dest_file_id VARCHAR(36) PATH '$[0]'" +
					", dest_parent_id VARCHAR(36) PATH '$[1]'" +
					", dest_parent VARCHAR(500) PATH '$[2]'" +
					", src_file_path VARCHAR(500) PATH '$[3]'" +
					")) AS items" +
					" JOIN files AS src_files ON src_files.file_path = items.src_file_path",
				Values: []any{
					sq.StringParam("destDirPath", destDirPath),
					sq.IntParam("start", len(srcDirPath)+1),
					sq.TimeParam("modTime", time.Now().UTC()),
					sq.StringParam("items", b.String()),
				},
			})
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported dialect %q", remoteFS.filesDialect)
		}
		wg.Wait()
		return nil
	}
	group, groupctx := errgroup.WithContext(ctx)
	err := fs.WalkDir(fsys.WithContext(groupctx), srcDirPath, func(filePath string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relPath := strings.TrimPrefix(strings.TrimSuffix(filePath, srcDirPath), "/")
		if dirEntry.IsDir() {
			err := fsys.WithContext(groupctx).MkdirAll(path.Join(destDirPath, relPath), 0755)
			if err != nil {
				return err
			}
			return nil
		}
		group.Go(func() error {
			srcFile, err := fsys.WithContext(groupctx).Open(filePath)
			if err != nil {
				return err
			}
			defer srcFile.Close()
			destFile, err := fsys.WithContext(groupctx).OpenWriter(path.Join(destDirPath, relPath), 0644)
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
	err = group.Wait()
	if err != nil {
		return nil
	}
	return nil
}

func encodeUUID(id [16]byte) string {
	var b [32 + 4]byte
	hex.Encode(b[:], id[:4])
	b[8] = '-'
	hex.Encode(b[9:13], id[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], id[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], id[8:10])
	b[23] = '-'
	hex.Encode(b[24:], id[10:])
	return string(b[:])
}
