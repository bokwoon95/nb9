package nb9

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/nb9/sq"
)

func (nbrew *Notebrew) directory(w http.ResponseWriter, r *http.Request, username, sitePrefix, folderPath string) {
}

func (nbrew *Notebrew) directory_Old(w http.ResponseWriter, r *http.Request, username, sitePrefix, folderPath string, fileInfo fs.FileInfo) {
	type FileEntry struct {
		Name    string
		IsDir   bool
		IsSite  bool
		IsUser  bool
		Size    int64
		ModTime time.Time
	}
	type Response struct {
		Status         string
		ContentDomain  string
		Username       string
		SitePrefix     string
		Path           string
		IsDir          bool
		ModTime        time.Time
		FileEntries    []FileEntry
		TemplateErrors []string
	}
	if r.Method != "GET" {
		methodNotAllowed(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
	err := r.ParseForm()
	if err != nil {
		badRequest(w, r, err)
		return
	}
	var response Response
	_, err = nbrew.getSession(r, "flash", &response)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	}
	nbrew.clearSession(w, r, "flash")
	response.ContentDomain = nbrew.ContentDomain
	response.Username = username
	response.SitePrefix = sitePrefix
	response.Path = folderPath
	response.IsDir = fileInfo.IsDir()
	if response.Status == "" {
		response.Status = "GetSuccess"
	}

	var authorizedForRootSite bool
	if folderPath == "" {
		for _, name := range []string{"notes", "pages", "posts", "output/themes", "output"} {
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, name))
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			} else if fileInfo.IsDir() {
				fileEntry := FileEntry{
					Name:    name,
					IsDir:   true,
					ModTime: fileInfo.ModTime(),
				}
				response.FileEntries = append(response.FileEntries, fileEntry)
			}
		}
		// {"next":"xxxx"}
		// sort=name&order=desc&from=xxxx&limit=100
		// from=xxxx&limit=100
		// from=xxxx
		if sitePrefix == "" {
			if nbrew.UsersDB != nil {
				results, err := sq.FetchAll(r.Context(), nbrew.UsersDB, sq.Query{
					Dialect: nbrew.UsersDialect,
					Format: "SELECT {*}" +
						" FROM site" +
						" JOIN site_user ON site_user.site_id = site.site_id" +
						" JOIN users ON users.user_id = site_user.user_id" +
						" WHERE users.username = {username}" +
						" ORDER BY site_prefix",
					Values: []any{
						sq.StringParam("username", username),
					},
				}, func(row *sq.Row) (result struct {
					SitePrefix string
					IsUser     bool
				}) {
					result.SitePrefix = row.String("CASE"+
						" WHEN site.site_name LIKE '%.%' THEN site.site_name"+
						" WHEN site.site_name <> '' THEN {concatSiteName}"+
						" ELSE ''"+
						" END AS site_prefix",
						sq.Param("concatSiteName", sq.DialectExpression{
							Default: sq.Expr("'@' || site.site_name"),
							Cases: []sq.DialectCase{{
								Dialect: "mysql",
								Result:  sq.Expr("concat('@', site.site_name)"),
							}},
						}),
					)
					result.IsUser = row.Bool("EXISTS (SELECT 1 FROM users WHERE users.username = site.site_name)")
					return result
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				for _, result := range results {
					if result.SitePrefix == "" {
						authorizedForRootSite = true
						continue
					}
					fileInfo, err := fs.Stat(nbrew.FS, path.Join(".", result.SitePrefix))
					if err != nil {
						if !errors.Is(err, fs.ErrNotExist) {
							getLogger(r.Context()).Error(err.Error())
							internalServerError(w, r, err)
							return
						}
					} else if fileInfo.IsDir() {
						response.FileEntries = append(response.FileEntries, FileEntry{
							Name:   result.SitePrefix,
							IsDir:  true,
							IsSite: true,
							IsUser: result.IsUser,
						})
					}
				}
				if !authorizedForRootSite {
					n := 0
					for _, fileEntry := range response.FileEntries {
						switch fileEntry.Name {
						case "notes", "pages", "posts", "output/themes", "output":
							continue
						default:
							response.FileEntries[n] = fileEntry
							n++
						}
					}
					response.FileEntries = response.FileEntries[:n]
				}
			} else {
				authorizedForRootSite = true
				dirEntries, err := nbrew.FS.ReadDir(".")
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				for _, dirEntry := range dirEntries {
					if !dirEntry.IsDir() {
						continue
					}
					name := dirEntry.Name()
					if !strings.Contains(name, ".") && !strings.HasPrefix(name, "@") {
						continue
					}
					response.FileEntries = append(response.FileEntries, FileEntry{
						Name:   name,
						IsDir:  true,
						IsSite: true,
					})
				}
			}
		}
	} else {
		head, _, _ := strings.Cut(folderPath, "/")
		if head != "notes" && head != "pages" && head != "posts" && head != "output" {
			notFound(w, r)
			return
		}
		dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, folderPath))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		for _, dirEntry := range dirEntries {
			fileInfo, err := dirEntry.Info()
			if err != nil {
				getLogger(r.Context()).Error(err.Error(), slog.String("name", dirEntry.Name()))
				internalServerError(w, r, err)
				return
			}
			fileEntry := FileEntry{
				Name:    dirEntry.Name(),
				IsDir:   dirEntry.IsDir(),
				Size:    fileInfo.Size(),
				ModTime: fileInfo.ModTime(),
			}
			ext := path.Ext(fileEntry.Name)
			switch head {
			case "notes", "output":
				if fileEntry.IsDir {
					response.FileEntries = append(response.FileEntries, fileEntry)
					continue
				}
				fileType := fileTypes[ext]
				if !strings.HasPrefix(fileType.ContentType, "text") && !strings.HasPrefix(fileType.ContentType, "image") {
					continue
				}
				response.FileEntries = append(response.FileEntries, fileEntry)
			case "pages":
				if fileEntry.IsDir {
					response.FileEntries = append(response.FileEntries, fileEntry)
					continue
				}
				if ext != ".html" {
					continue
				}
				response.FileEntries = append(response.FileEntries, fileEntry)
			case "posts":
				if fileEntry.IsDir {
					if strings.Contains(folderPath, "/") {
						continue
					}
					response.FileEntries = append(response.FileEntries, fileEntry)
					continue
				}
				if ext != ".md" {
					continue
				}
				prefix, _, ok := strings.Cut(fileEntry.Name, "-")
				if !ok || prefix == "" || len(prefix) > 8 {
					continue
				}
				b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
				if len(b) != 5 {
					continue
				}
				response.FileEntries = append(response.FileEntries, fileEntry)
			}
		}
	}

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

	contentURL := nbrew.contentSite(sitePrefix)
	funcMap := map[string]any{
		"join":                  path.Join,
		"base":                  path.Base,
		"ext":                   path.Ext,
		"hasPrefix":             strings.HasPrefix,
		"trimPrefix":            strings.TrimPrefix,
		"contains":              strings.Contains,
		"fileSizeToString":      fileSizeToString,
		"stylesCSS":             func() template.CSS { return template.CSS(stylesCSS) },
		"folderJS":              func() template.JS { return template.JS(directoryJS) },
		"contentURL":            func() string { return contentURL },
		"hasDatabase":           func() bool { return nbrew.UsersDB != nil },
		"referer":               func() string { return r.Referer() },
		"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
		"authorizedForRootSite": func() bool { return authorizedForRootSite },
		"head": func(s string) string {
			head, _, _ := strings.Cut(s, "/")
			return head
		},
		"tail": func(s string) string {
			_, tail, _ := strings.Cut(s, "/")
			return tail
		},
		"generateBreadcrumbLinks": func(filePath string) template.HTML {
			var b strings.Builder
			b.WriteString(`<a href="/files/">files</a>`)
			segments := strings.Split(filePath, "/")
			if sitePrefix != "" {
				segments = append([]string{sitePrefix}, segments...)
			}
			for i := 0; i < len(segments); i++ {
				if segments[i] == "" {
					continue
				}
				href := `/files/` + path.Join(segments[:i+1]...) + `/`
				if i == len(segments)-1 && !response.IsDir {
					href = strings.TrimSuffix(href, `/`)
				}
				b.WriteString(` / <a href="` + href + `">` + segments[i] + `</a>`)
			}
			if response.IsDir {
				b.WriteString(` /`)
			}
			return template.HTML(b.String())
		},
	}
	tmpl, err := template.New("directory.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/directory.html")
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	executeTemplate(w, r, fileInfo.ModTime(), tmpl, &response)
}
