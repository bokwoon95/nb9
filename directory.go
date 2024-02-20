package nb9

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
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

func (nbrew *Notebrew) directory(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string, modTime time.Time) {
	type File struct {
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size,omitempty"`
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

		Sort        string `json:"sort,omitempty"`
		Order       string `json:"order,omitempty"`
		From        string `json:"from,omitempty"`
		FromTime    string `json:"fromTime,omitempty"`
		Before      string `json:"before,omitempty"`
		BeforeTime  string `json:"beforeTime,omitempty"`
		Limit       int    `json:"limit,omitempty"`
		Files       []File `json:"files"`
		PreviousURL string `json:"previousURL,omitempty"`
		NextURL     string `json:"nextURL,omitempty"`
	}
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
		if response.Files == nil {
			response.Files = []File{}
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
			"generateBreadcrumbLinks": func(sitePrefix, filePath string) template.HTML {
				var b strings.Builder
				b.WriteString("<a href='/files/'>files</a>")
				segments := strings.Split(filePath, "/")
				if sitePrefix != "" {
					segments = append([]string{sitePrefix}, segments...)
				}
				for i := 0; i < len(segments); i++ {
					if segments[i] == "" {
						continue
					}
					href := "/files/" + path.Join(segments[:i+1]...) + "/"
					b.WriteString(" / <a href='" + href + "'>" + segments[i] + "</a>")
				}
				b.WriteString(" /")
				return template.HTML(b.String())
			},
			"isInClipboard": func(name string) bool {
				if sitePrefix != clipboard.Get("sitePrefix") {
					return false
				}
				if response.FilePath != clipboard.Get("parent") {
					return false
				}
				return isInClipboard[name]
			},
		}
		tmpl, err := template.New("directory.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/directory.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		executeTemplate(w, r, tmpl, &response)
	}

	head, _, _ := strings.Cut(filePath, "/")
	if head != "notes" && head != "pages" && head != "posts" && head != "output" {
		notFound(w, r)
		return
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
	response.FilePath = filePath
	response.IsDir = true
	_, response.SearchSupported = nbrew.FS.(*RemoteFS)
	response.Sort = strings.ToLower(strings.TrimSpace(r.Form.Get("sort")))
	if response.Sort == "" {
		cookie, _ := r.Cookie("sort")
		if cookie != nil {
			response.Sort = cookie.Value
		}
	}
	switch response.Sort {
	case "name", "edited", "created":
		break
	default:
		if head == "notes" {
			response.Sort = "edited"
		} else if head == "posts" {
			response.Sort = "created"
		} else {
			response.Sort = "name"
		}
	}
	if r.Form.Has("sort") {
		if (head == "notes" && response.Sort == "edited") || (head == "posts" && response.Sort == "created") || response.Sort == "name" {
			http.SetCookie(w, &http.Cookie{
				Path:     r.URL.Path,
				Name:     "sort",
				Value:    "0",
				MaxAge:   -1,
				Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		} else {
			http.SetCookie(w, &http.Cookie{
				Path:     r.URL.Path,
				Name:     "sort",
				Value:    response.Sort,
				MaxAge:   int((time.Hour * 24 * 365).Seconds()),
				Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}
	}
	response.Order = strings.ToLower(strings.TrimSpace(r.Form.Get("order")))
	if response.Order == "" {
		cookie, _ := r.Cookie("order")
		if cookie != nil {
			response.Order = cookie.Value
		}
	}
	switch response.Order {
	case "asc", "desc":
		break
	default:
		if response.Sort == "created" || response.Sort == "edited" {
			response.Order = "desc"
		} else {
			response.Order = "asc"
		}
	}
	if r.Form.Has("order") {
		if ((response.Sort == "created" || response.Sort == "edited") && response.Order == "desc") || response.Order == "asc" {
			http.SetCookie(w, &http.Cookie{
				Path:     r.URL.Path,
				Name:     "order",
				Value:    "0",
				MaxAge:   -1,
				Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		} else {
			http.SetCookie(w, &http.Cookie{
				Path:     r.URL.Path,
				Name:     "order",
				Value:    response.Order,
				MaxAge:   int((time.Hour * 24 * 365).Seconds()),
				Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}
	}

	remoteFS, ok := nbrew.FS.(*RemoteFS)
	if !ok {
		dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(path.Join(sitePrefix, filePath))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		for _, dirEntry := range dirEntries {
			fileInfo, err := dirEntry.Info()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			name := fileInfo.Name()
			var absolutePath string
			if localFS, ok := nbrew.FS.(*LocalFS); ok {
				absolutePath = path.Join(localFS.rootDir, sitePrefix, filePath, name)
			}
			file := File{
				Name:         name,
				IsDir:        fileInfo.IsDir(),
				Size:         fileInfo.Size(),
				ModTime:      fileInfo.ModTime(),
				CreationTime: CreationTime(absolutePath, fileInfo),
			}
			if file.IsDir {
				response.Files = append(response.Files, file)
				continue
			}
			_, ok := fileTypes[path.Ext(file.Name)]
			if !ok {
				continue
			}
			response.Files = append(response.Files, file)
		}
		switch response.Sort {
		case "name":
			if response.Order == "desc" {
				slices.Reverse(response.Files)
			}
		case "edited":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.ModTime.Equal(b.ModTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.ModTime.Before(b.ModTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		case "created":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.CreationTime.Equal(b.CreationTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.CreationTime.Before(b.CreationTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		}
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

	if response.Sort == "name" {
		response.From = r.Form.Get("from")
		if response.From != "" {
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Order == "asc" {
					filter = sq.Expr("file_path >= {}", path.Join(sitePrefix, filePath, response.From))
					order = sq.Expr("file_path ASC")
				} else {
					filter = sq.Expr("file_path <= {}", path.Join(sitePrefix, filePath, response.From))
					order = sq.Expr("file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						Size:         row.Int64("size"),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						IsDir:        row.Bool("is_dir"),
					}
				})
				if err != nil {
					return err
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme:   scheme,
						Host:     r.Host,
						Path:     r.URL.Path,
						RawQuery: "from=" + url.QueryEscape(nextFile.Name) + "&limit=" + strconv.Itoa(response.Limit),
					}
					response.NextURL = uri.String()
				}
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Order == "asc" {
					filter = sq.Expr("file_path < {}", path.Join(sitePrefix, filePath, response.From))
					order = sq.Expr("file_path DESC")
				} else {
					filter = sq.Expr("file_path > {}", path.Join(sitePrefix, filePath, response.From))
					order = sq.Expr("file_path ASC")
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return err
				}
				if hasPreviousFile {
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
				var filter, order sq.Expression
				if response.Order == "asc" {
					filter = sq.Expr("file_path < {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path ASC")
				} else {
					filter = sq.Expr("file_path > {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						Size:         row.Int64("size"),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						IsDir:        row.Bool("is_dir"),
					}
				})
				if err != nil {
					return err
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					response.Files = response.Files[1:]
					uri := &url.URL{
						Scheme:   scheme,
						Host:     r.Host,
						Path:     r.URL.Path,
						RawQuery: "before=" + url.QueryEscape(response.Files[0].Name) + "&limit=" + strconv.Itoa(response.Limit),
					}
					response.PreviousURL = uri.String()
				}
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Order == "asc" {
					filter = sq.Expr("file_path >= {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path DESC")
				} else {
					filter = sq.Expr("file_path <= {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path ASC")
				}
				nextFile, err := sq.FetchOne(groupctx, remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
					}
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
					RawQuery: "from=" + url.QueryEscape(nextFile.Name) + "&limit=" + strconv.Itoa(response.Limit),
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
	}

	const timeFormat = "2006-01-02T150405.999999999Z"
	if response.Sort == "edited" || response.Sort == "created" {
		fromTime, _ := time.ParseInLocation(timeFormat, r.Form.Get("fromTime"), time.UTC)
		from := r.Form.Get("from")
		if !fromTime.IsZero() && from != "" {
			response.FromTime = fromTime.Format(timeFormat)
			response.From = from
			timeParam := sq.TimeParam("timeParam", fromTime)
			pathParam := sq.StringParam("pathParam", path.Join(response.SitePrefix, response.FilePath, response.From))
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Sort == "edited" {
					if response.Order == "asc" {
						filter = sq.Expr("mod_time >= {timeParam} AND file_path >= {pathParam}", timeParam, pathParam)
						order = sq.Expr("mod_time ASC, file_path ASC")
					} else {
						filter = sq.Expr("mod_time <= {timeParam} AND file_path <= {pathParam}", timeParam, pathParam)
						order = sq.Expr("mod_time DESC, file_path DESC")
					}
				} else if response.Sort == "created" {
					if response.Order == "asc" {
						filter = sq.Expr("creation_time >= {timeParam} AND file_path >= {pathParam}", timeParam, pathParam)
						order = sq.Expr("creation_time ASC, file_path ASC")
					} else {
						filter = sq.Expr("creation_time <= {timeParam} AND file_path <= {pathParam}", timeParam, pathParam)
						order = sq.Expr("creation_time DESC, file_path DESC")
					}
				}
				files, err := sq.FetchAll(groupctx, remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						Size:         row.Int64("size"),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						IsDir:        row.Bool("is_dir"),
					}
				})
				if err != nil {
					return err
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
					}
					if response.Sort == "edited" {
						uri.RawQuery = "fromTime=" + url.QueryEscape(nextFile.ModTime.UTC().Format(timeFormat)) + "&from=" + url.QueryEscape(nextFile.Name) + "&limit=" + strconv.Itoa(response.Limit)
					} else if response.Sort == "created" {
						uri.RawQuery = "fromTime=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(timeFormat)) + "&from=" + url.QueryEscape(nextFile.Name) + "&limit=" + strconv.Itoa(response.Limit)
					}
					response.NextURL = uri.String()
				}
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Sort == "edited" {
					if response.Order == "asc" {
						filter = sq.Expr("(mod_time < {timeParam} OR (mod_time = {timeParam} AND file_path < {pathParam})", timeParam, pathParam)
						order = sq.Expr("mod_time DESC, file_path DESC")
					} else {
						filter = sq.Expr("(mod_time > {timeParam} OR (mod_time = {timeParam} AND file_path > {pathParam}))", timeParam, pathParam)
						order = sq.Expr("mod_time ASC, file_path ASC")
					}
				} else if response.Sort == "created" {
					if response.Order == "asc" {
						filter = sq.Expr("(creation_time < {timeParam} OR (creation_time = {timeParam} AND file_path < {pathParam}))", timeParam, pathParam)
						order = sq.Expr("creation_time DESC, file_path DESC")
					} else {
						filter = sq.Expr("(creation_time > {timeParam} OR (creation_time = {timeParam} AND file_path > {pathParam}))", timeParam, pathParam)
						order = sq.Expr("creation_time ASC, file_path ASC")
					}
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return err
				}
				if hasPreviousFile {
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
					}
					if response.From != "" {
						uri.RawQuery = "beforeTime=" + url.QueryEscape(response.FromTime) + "&before=" + url.QueryEscape(response.From) + "&limit=" + strconv.Itoa(response.Limit)
					} else {
						uri.RawQuery = "beforeTime=" + url.QueryEscape(response.FromTime) + "&limit=" + strconv.Itoa(response.Limit)
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
		beforeTime, _ := time.ParseInLocation(timeFormat, r.Form.Get("beforeTime"), time.UTC)
		before := r.Form.Get("before")
		if !beforeTime.IsZero() && before != "" {
			response.BeforeTime = beforeTime.Format(timeFormat)
			response.Before = before
			timeParam := sq.TimeParam("timeParam", beforeTime)
			pathParam := sq.StringParam("pathParam", path.Join(response.SitePrefix, response.FilePath, response.Before))
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Sort == "edited" {
					if response.Order == "asc" {
						filter = sq.Expr("(mod_time < {timeParam} OR (mod_time = {timeParam} AND file_path < {pathParam}))", timeParam, pathParam)
						order = sq.Expr("mod_time ASC, file_path ASC")
					} else {
						filter = sq.Expr("(mod_time > {timeParam} OR (mod_time = {timeParam} AND file_path > {pathParam}))", timeParam, pathParam)
						order = sq.Expr("mod_time DESC, file_path DESC")
					}
				} else if response.Sort == "created" {
					if response.Order == "asc" {
						filter = sq.Expr("(creation_time < {timeParam} OR (creation_time = {timeParam} AND file_path < {pathParam}))", timeParam, pathParam)
						order = sq.Expr("creation_time ASC, file_path ASC")
					} else {
						filter = sq.Expr("(creation_time > {timeParam} OR (creation_time = {timeParam} AND file_path > {pathParam}))", timeParam, pathParam)
						order = sq.Expr("creation_time DESC, file_path DESC")
					}
				}
				files, err := sq.FetchAll(groupctx, remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						Size:         row.Int64("size"),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
						IsDir:        row.Bool("is_dir"),
					}
				})
				if err != nil {
					return err
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					response.Files = response.Files[1:]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
					}
					if response.Sort == "edited" {
						uri.RawQuery = "beforeTime=" + url.QueryEscape(response.Files[0].ModTime.UTC().Format(timeFormat)) + "&before=" + url.QueryEscape(response.Files[0].Name) + "&limit=" + strconv.Itoa(response.Limit)
					} else if response.Sort == "created" {
						uri.RawQuery = "beforeTime=" + url.QueryEscape(response.Files[0].CreationTime.UTC().Format(timeFormat)) + "&before=" + url.QueryEscape(response.Files[0].Name) + "&limit=" + strconv.Itoa(response.Limit)
					}
					response.PreviousURL = uri.String()
				}
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Sort == "edited" {
					if response.Order == "asc" {
						filter = sq.Expr("mod_time >= {timeParam} AND file_path >= {pathParam}", timeParam, pathParam)
						order = sq.Expr("mod_time ASC, file_path ASC")
					} else {
						filter = sq.Expr("mod_time <= {timeParam} AND file_path <= {pathParam}", timeParam, pathParam)
						order = sq.Expr("mod_time DESC, file_path DESC")
					}
				} else if response.Sort == "created" {
					if response.Order == "asc" {
						filter = sq.Expr("creation_time >= {timeParam} AND file_path >= {pathParam}", timeParam, pathParam)
						order = sq.Expr("creation_time ASC, file_path ASC")
					} else {
						filter = sq.Expr("creation_time <= {timeParam} AND file_path <= {pathParam}", timeParam, pathParam)
						order = sq.Expr("creation_time DESC, file_path DESC")
					}
				}
				nextFile, err := sq.FetchOne(groupctx, remoteFS.filesDB, sq.Query{
					Dialect: remoteFS.filesDialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return err
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
				}
				if response.Sort == "edited" {
					uri.RawQuery = "fromTime=" + url.QueryEscape(nextFile.ModTime.UTC().Format(timeFormat)) + "&from=" + url.QueryEscape(nextFile.Name) + "&limit=" + strconv.Itoa(response.Limit)
				} else if response.Sort == "created" {
					uri.RawQuery = "fromTime=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(timeFormat)) + "&from=" + url.QueryEscape(nextFile.Name) + "&limit=" + strconv.Itoa(response.Limit)
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
	}

	var order sq.Expression
	if response.Sort == "name" {
		if response.Order == "asc" {
			order = sq.Expr("file_path ASC")
		} else {
			order = sq.Expr("file_path DESC")
		}
	} else if response.Sort == "edited" {
		if response.Order == "asc" {
			order = sq.Expr("mod_time ASC, file_path ASC")
		} else {
			order = sq.Expr("mod_time DESC, file_path DESC")
		}
	} else if response.Sort == "created" {
		if response.Order == "asc" {
			order = sq.Expr("creation_time ASC, file_path ASC")
		} else {
			order = sq.Expr("creation_time DESC, file_path DESC")
		}
	}
	files, err := sq.FetchAll(r.Context(), remoteFS.filesDB, sq.Query{
		Dialect: remoteFS.filesDialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
			" ORDER BY {order}" +
			" LIMIT {limit} + 1",
		Values: []any{
			sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
			sq.Param("order", order),
			sq.IntParam("limit", response.Limit),
		},
	}, func(row *sq.Row) File {
		return File{
			Name:         path.Base(row.String("file_path")),
			Size:         row.Int64("size"),
			ModTime:      row.Time("mod_time"),
			CreationTime: row.Time("creation_time"),
			IsDir:        row.Bool("is_dir"),
		}
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	response.Files = files
	if len(response.Files) > response.Limit {
		nextFile := response.Files[response.Limit]
		response.Files = response.Files[:response.Limit]
		uri := &url.URL{
			Scheme: scheme,
			Host:   r.Host,
			Path:   r.URL.Path,
		}
		if response.Sort == "name" {
			uri.RawQuery = "from=" + url.QueryEscape(nextFile.Name) + "&limit=" + strconv.Itoa(response.Limit)
		} else if response.Sort == "edited" {
			uri.RawQuery = "fromTime=" + url.QueryEscape(nextFile.ModTime.UTC().Format(timeFormat)) + "&from=" + url.QueryEscape(nextFile.Name) + "&limit=" + strconv.Itoa(response.Limit)
		} else if response.Sort == "created" {
			uri.RawQuery = "fromTime=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(timeFormat)) + "&from=" + url.QueryEscape(nextFile.Name) + "&limit=" + strconv.Itoa(response.Limit)
		}
		response.NextURL = uri.String()
	}
	writeResponse(w, r, response)
	return
}
