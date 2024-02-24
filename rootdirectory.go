package nb9

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/nb9/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) rootdirectory(w http.ResponseWriter, r *http.Request, username, sitePrefix string, modTime time.Time) {
	type File struct {
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size,omitempty"`
	}
	type Site struct {
		Name  string `json:"name"`
		Owner string `json:"owner,omitempty"`
	}
	type Response struct {
		PostRedirectGet map[string]any `json:"postRedirectGet,omitempty"`
		TemplateError   TemplateError  `json:"templateError,omitempty"`
		ContentSite     string         `json:"contentSite"`
		Username        NullString     `json:"username"`
		SitePrefix      string         `json:"sitePrefix"`
		FilePath        string         `json:"filePath"`
		IsDir           bool           `json:"isDir"`
		SearchSupported bool           `json:"searchSupported"`

		Files []File `json:"files,omitempty"`

		From        string `json:"from,omitempty"`
		Before      string `json:"before,omitempty"`
		Limit       int    `json:"limit"`
		Sites       []Site `json:"sites"`
		PreviousURL string `json:"previousURL,omitempty"`
		NextURL     string `json:"nextURL,omitempty"`
	}
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
		if response.Sites == nil {
			response.Sites = []Site{}
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
		referer := getReferer(r)
		clipboard := make(url.Values)
		isInClipboard := make(map[string]bool)
		cookie, _ := r.Cookie("clipboard")
		if cookie != nil {
			values, err := url.ParseQuery(cookie.Value)
			if err == nil {
				if values.Has("cut") {
					clipboard.Set("cut", "")
				}
				clipboard.Set("sitePrefix", values.Get("sitePrefix"))
				clipboard.Set("parent", values.Get("parent"))
				for _, name := range values["name"] {
					if isInClipboard[name] {
						continue
					}
					clipboard.Add("name", name)
					isInClipboard[name] = true
				}
			}
		}
		funcMap := map[string]any{
			"join":             path.Join,
			"dir":              path.Dir,
			"base":             path.Base,
			"ext":              path.Ext,
			"hasPrefix":        strings.HasPrefix,
			"hasSuffix":        strings.HasSuffix,
			"trimPrefix":       strings.TrimPrefix,
			"trimSuffix":       strings.TrimSuffix,
			"fileSizeToString": fileSizeToString,
			"stylesCSS":        func() template.CSS { return template.CSS(stylesCSS) },
			"baselineJS":       func() template.JS { return template.JS(baselineJS) },
			"referer":          func() string { return referer },
			"clipboard":        func() url.Values { return clipboard },
			"safeHTML":         func(s string) template.HTML { return template.HTML(s) },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
		}
		tmpl, err := template.New("rootdirectory.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/rootdirectory.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		executeTemplate(w, r, tmpl, &response)
	}

	var response Response
	_, err := nbrew.getSession(r, "flash", &response)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	}
	nbrew.clearSession(w, r, "flash")
	response.ContentSite = nbrew.contentSite(sitePrefix)
	response.Username = NullString{String: username, Valid: nbrew.UsersDB != nil}
	response.SitePrefix = sitePrefix
	response.IsDir = true
	_, response.SearchSupported = nbrew.FS.(*RemoteFS)
	if sitePrefix == "" && nbrew.UsersDB != nil {
		sites, err := sq.FetchAll(r.Context(), nbrew.UsersDB, sq.Query{
			Dialect: nbrew.UsersDialect,
			Format: "SELECT {*}" +
				" FROM site_user" +
				" JOIN site ON site.site_id = site_user.site_id" +
				" JOIN users ON users.user_id = site_user.site_id" +
				" LEFT JOIN site_owner ON site_owner.site_id = site_user.site_id" +
				" LEFT JOIN users AS owner ON owner.user_id = site_owner.user_id" +
				" WHERE users.username = {username}" +
				" ORDER BY site_prefix",
			Values: []any{
				sq.StringParam("username", username),
			},
		}, func(row *sq.Row) Site {
			return Site{
				Name: row.String("CASE" +
					" WHEN site.site_name LIKE '%.%' THEN site.site_name" +
					" WHEN site.site_name <> '' THEN concat('@', site.site_name)" +
					" ELSE ''" +
					" END AS site_prefix",
				),
				Owner: row.String("owner.username"),
			}
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		response.Sites = sites
		n := slices.IndexFunc(response.Sites, func(site Site) bool { return site.Name == "" })
		if n < 0 {
			writeResponse(w, r, response)
			return
		}
		copy(response.Sites[n:], response.Sites[n+1:])
		response.Sites = response.Sites[:len(response.Sites)-1]
	}

	remoteFS, ok := nbrew.FS.(*RemoteFS)
	if !ok {
		for _, dir := range []string{"notes", "pages", "posts", "output/themes", "output"} {
			fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, dir))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			if !fileInfo.IsDir() {
				continue
			}
			var absolutePath string
			if localFS, ok := nbrew.FS.(*LocalFS); ok {
				absolutePath = path.Join(localFS.rootDir, sitePrefix, dir)
			}
			response.Files = append(response.Files, File{
				Name:         fileInfo.Name(),
				IsDir:        true,
				ModTime:      fileInfo.ModTime(),
				CreationTime: CreationTime(absolutePath, fileInfo),
			})
		}

		if sitePrefix != "" || nbrew.UsersDB != nil {
			writeResponse(w, r, response)
			return
		}

		dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(".")
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
			if strings.HasPrefix(name, "@") || strings.Contains(name, ".") {
				response.Sites = append(response.Sites, Site{Name: name})
			}
		}
		writeResponse(w, r, response)
		return
	}

	files, err := sq.FetchAll(r.Context(), remoteFS.DB, sq.Query{
		Dialect: remoteFS.Dialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE file_path IN ({notes}, {pages}, {posts}, {themes}, {output})" +
			" AND is_dir" +
			" ORDER BY CASE file_path" +
			" WHEN {notes} THEN 1" +
			" WHEN {pages} THEN 2" +
			" WHEN {posts} THEN 3" +
			" WHEN {themes} THEN 4" +
			" WHEN {output} THEN 5" +
			" END",
		Values: []any{
			sq.StringParam("notes", path.Join(sitePrefix, "notes")),
			sq.StringParam("pages", path.Join(sitePrefix, "pages")),
			sq.StringParam("posts", path.Join(sitePrefix, "posts")),
			sq.StringParam("themes", path.Join(sitePrefix, "output/themes")),
			sq.StringParam("output", path.Join(sitePrefix, "output")),
		},
	}, func(row *sq.Row) File {
		return File{
			Name:         strings.Trim(strings.TrimPrefix(row.String("file_path"), sitePrefix), "/"),
			ModTime:      row.Time("mod_time"),
			CreationTime: row.Time("creation_time"),
			IsDir:        true,
		}
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	response.Files = files

	if sitePrefix != "" || nbrew.UsersDB != nil {
		writeResponse(w, r, response)
		return
	}

	response.Limit, _ = strconv.Atoi(r.Form.Get("limit"))
	if response.Limit <= 0 {
		response.Limit = 1000
	}
	scheme := "https"
	if nbrew.CMSDomain == "localhost" || strings.HasPrefix(nbrew.CMSDomain, "localhost:") {
		scheme = "http"
	}

	response.From = r.Form.Get("from")
	if response.From != "" {
		group, groupctx := errgroup.WithContext(r.Context())
		group.Go(func() error {
			sites, err := sq.FetchAll(groupctx, remoteFS.DB, sq.Query{
				Dialect: remoteFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' OR file_path LIKE '%.%')" +
					" AND file_path >= {from}" +
					" ORDER BY file_path" +
					" LIMIT {limit} + 1",
				Values: []any{
					sq.StringParam("from", response.From),
					sq.IntParam("limit", response.Limit),
				},
			}, func(row *sq.Row) Site {
				return Site{
					Name: row.String("files.file_path"),
				}
			})
			if err != nil {
				return err
			}
			response.Sites = sites
			if len(response.Sites) > response.Limit {
				uri := &url.URL{
					Scheme:   scheme,
					Host:     r.Host,
					Path:     r.URL.Path,
					RawQuery: "from=" + url.QueryEscape(response.Sites[response.Limit].Name) + "&limit=" + strconv.Itoa(response.Limit),
				}
				response.Sites = response.Sites[:response.Limit]
				response.NextURL = uri.String()
			}
			return nil
		})
		group.Go(func() error {
			hasPreviousSite, err := sq.FetchExists(groupctx, remoteFS.DB, sq.Query{
				Dialect: remoteFS.Dialect,
				Format: "SELECT 1" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' OR file_path LIKE '%.%')" +
					" AND file_path < {from}",
				Values: []any{
					sq.StringParam("from", response.From),
				},
			})
			if err != nil {
				return err
			}
			if hasPreviousSite {
				uri := &url.URL{
					Scheme:   scheme,
					Host:     r.Host,
					Path:     r.URL.Path,
					RawQuery: "before=" + url.QueryEscape(response.From) + "&limit=" + strconv.Itoa(response.Limit),
				}
				response.PreviousURL = uri.String()
			}
			return nil
		})
		err := group.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
		return
	}

	response.Before = r.Form.Get("before")
	if response.Before != "" {
		group, groupctx := errgroup.WithContext(r.Context())
		group.Go(func() error {
			response.Sites, err = sq.FetchAll(groupctx, remoteFS.DB, sq.Query{
				Dialect: remoteFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND (file_path LIKE '@%' OR file_path LIKE '%.%')" +
					" AND file_path < {before}" +
					" ORDER BY file_path" +
					" LIMIT {limit} + 1",
				Values: []any{
					sq.StringParam("before", response.Before),
					sq.IntParam("limit", response.Limit),
				},
			}, func(row *sq.Row) Site {
				return Site{
					Name: row.String("files.file_path"),
				}
			})
			if err != nil {
				return err
			}
			if len(response.Sites) > response.Limit {
				response.Sites = response.Sites[1:]
				uri := &url.URL{
					Scheme:   scheme,
					Host:     r.Host,
					Path:     r.URL.Path,
					RawQuery: "before=" + url.QueryEscape(response.Sites[0].Name) + "&limit=" + strconv.Itoa(response.Limit),
				}
				response.PreviousURL = uri.String()
			}
			return nil
		})
		group.Go(func() error {
			nextSite, err := sq.FetchOne(groupctx, remoteFS.DB, sq.Query{
				Dialect: remoteFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id IS NULL" +
					" AND is_dir" +
					" AND file_path >= {before}" +
					" ORDER BY file_path" +
					" LIMIT 1",
				Values: []any{
					sq.StringParam("before", response.Before),
				},
			}, func(row *sq.Row) string {
				return row.String("file_path")
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil
				}
				return err
			}
			uri := &url.URL{
				Scheme:   scheme,
				Host:     r.Host,
				Path:     r.URL.Path,
				RawQuery: "from=" + url.QueryEscape(nextSite) + "&limit=" + strconv.Itoa(response.Limit),
			}
			response.NextURL = uri.String()
			return nil
		})
		err := group.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
		return
	}

	sites, err := sq.FetchAll(r.Context(), remoteFS.DB, sq.Query{
		Dialect: remoteFS.Dialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE parent_id IS NULL" +
			" AND is_dir" +
			" AND (file_path LIKE '@%' OR file_path LIKE '%.%')" +
			" ORDER BY file_path" +
			" LIMIT {limit} + 1",
		Values: []any{
			sq.IntParam("limit", response.Limit),
		},
	}, func(row *sq.Row) Site {
		return Site{
			Name: row.String("files.file_path"),
		}
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	response.Sites = sites
	if len(response.Sites) > response.Limit {
		uri := &url.URL{
			Scheme:   scheme,
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: "from=" + url.QueryEscape(response.Sites[response.Limit].Name) + "&limit=" + strconv.Itoa(response.Limit),
		}
		response.Sites = response.Sites[:response.Limit]
		response.NextURL = uri.String()
	}
	writeResponse(w, r, response)
	return
}
