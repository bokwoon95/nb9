package nb9

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/bokwoon95/nb9/sq"
)

func (nbrew *Notebrew) createsite(w http.ResponseWriter, r *http.Request, username string) {
	type Request struct {
		SiteName string `json:"siteName"`
	}
	type Response struct {
		Error         string     `json:"error"`
		FormErrors    url.Values `json:"formErrors,omitempty"`
		Username      NullString `json:"username"`
		SiteName      string     `json:"siteName,omitempty"`
		UserSiteNames []string   `json:"userSiteNames,omitempty"`
	}
	const maxSites = 3

	getSiteInfo := func(username string) (userSiteNames []string, maxSitesReached bool, err error) {
		if nbrew.UsersDB == nil {
			return nil, false, nil
		}
		userSiteNames, err = sq.FetchAll(r.Context(), nbrew.UsersDB, sq.Query{
			Dialect: nbrew.UsersDialect,
			Format: "SELECT {*}" +
				" FROM site" +
				" JOIN site_owner ON site_owner.site_id = site.site_id" +
				" JOIN users ON users.user_id = site_owner.user_id" +
				" WHERE users.username = {username}",
			Values: []any{
				sq.StringParam("username", username),
			},
		}, func(row *sq.Row) string {
			return row.String("site.site_name")
		})
		if err != nil {
			return nil, false, err
		}
		n := 0
		var unlimitedSites bool
		for _, siteName := range userSiteNames {
			if siteName == "" {
				unlimitedSites = true
				continue
			}
			userSiteNames[n] = siteName
			n++
		}
		userSiteNames = userSiteNames[:n]
		return userSiteNames, !unlimitedSites && len(userSiteNames) >= maxSites, nil
	}

	switch r.Method {
	case "GET":
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
			funcMap := map[string]any{
				"join":       path.Join,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"contains":   strings.Contains,
				"stylesCSS":  func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS": func() template.JS { return template.JS(baselineJS) },
				"referer":    func() string { return r.Referer() },
				"username":   func() string { return username },
				"maxSites":   func() int { return maxSites },
			}
			tmpl, err := template.New("createsite.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/createsite.html")
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
		response.Username = NullString{String: username, Valid: nbrew.UsersDB != nil}
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		userSiteNames, maxSitesReached, err := getSiteInfo(username)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		response.UserSiteNames = userSiteNames
		if maxSitesReached {
			response.Error = "MaxSitesReached"
			writeResponse(w, r, response)
			return
		}
		writeResponse(w, r, response)
	case "POST":
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
				err := nbrew.setSession(w, r, "flash", &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/files/createsite/", http.StatusFound)
				return
			}
			sitePrefix := response.SiteName
			if !strings.Contains(response.SiteName, ".") {
				sitePrefix = "@" + response.SiteName
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]string{
					"from":       "createsite",
					"sitePrefix": sitePrefix,
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/files/", http.StatusFound)
		}

		var request Request
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
				if err != nil {
					badRequest(w, r, err)
					return
				}
			} else {
				err := r.ParseForm()
				if err != nil {
					badRequest(w, r, err)
					return
				}
			}
			request.SiteName = r.Form.Get("siteName")
		default:
			unsupportedContentType(w, r)
			return
		}

		var err error
		response := Response{
			SiteName:   request.SiteName,
			FormErrors: url.Values{},
		}
		userSiteNames, maxSitesReached, err := getSiteInfo(username)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		response.UserSiteNames = userSiteNames
		if maxSitesReached {
			response.Error = "MaxSitesReached"
			writeResponse(w, r, response)
			return
		}

		if response.SiteName == "" {
			response.FormErrors.Add("siteName", "required")
		} else {
			hasForbiddenCharacters := false
			digitCount := 0
			for _, char := range response.SiteName {
				if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
					hasForbiddenCharacters = true
				}
				if char >= '0' && char <= '9' {
					digitCount++
				}
			}
			if hasForbiddenCharacters {
				response.FormErrors.Add("siteName", "only lowercase letters, numbers and hyphen allowed")
			}
			if len(response.SiteName) > 30 {
				response.FormErrors.Add("siteName", "cannot exceed 30 characters")
			}
		}
		var sitePrefix string
		if strings.Contains(response.SiteName, ".") {
			sitePrefix = response.SiteName
		} else if response.SiteName != "" {
			sitePrefix = "@" + response.SiteName
		}
		if response.SiteName == "www" || response.SiteName == "cdn" {
			response.FormErrors.Add("siteName", "unavailable")
		} else if !response.FormErrors.Has("siteName") {
			_, err := fs.Stat(nbrew.FS, sitePrefix)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				if nbrew.UsersDB != nil {
					exists, err := sq.FetchExists(r.Context(), nbrew.UsersDB, sq.Query{
						Dialect: nbrew.UsersDialect,
						Format:  "SELECT 1 FROM site WHERE site_name = {siteName}",
						Values: []any{
							sq.StringParam("siteName", response.SiteName),
						},
					})
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
					if exists {
						response.FormErrors.Add("siteName", "unavailable")
					}
				}
			} else {
				response.FormErrors.Add("siteName", "unavailable")
			}
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}

		err = nbrew.FS.Mkdir(sitePrefix, 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		dirs := []string{
			"notes",
			"output",
			"output/images",
			"output/themes",
			"pages",
			"posts",
		}
		for _, dir := range dirs {
			err = nbrew.FS.Mkdir(path.Join(sitePrefix, dir), 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		for _, pair := range [][2]string{
			{"pages/index.html", "embed/index.html"},
			{"output/themes/post.html", "embed/post.html"},
			{"output/themes/postlist.html", "embed/postlist.html"},
		} {
			destName, srcName := pair[0], pair[1]
			file, err := RuntimeFS.Open(srcName)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			writer, err := nbrew.FS.OpenWriter(destName, 0644)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			_, err = io.Copy(writer, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			err = writer.Close()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			err = file.Close()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		if nbrew.UsersDB != nil {
			tx, err := nbrew.UsersDB.Begin()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			defer tx.Rollback()
			siteID := NewID()
			_, err = sq.Exec(r.Context(), tx, sq.Query{
				Dialect: nbrew.UsersDialect,
				Format:  "INSERT INTO site (site_id, site_name) VALUES ({siteID}, {siteName})",
				Values: []any{
					sq.UUIDParam("siteID", siteID),
					sq.StringParam("siteName", request.SiteName),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			_, err = sq.Exec(r.Context(), tx, sq.Query{
				Dialect: nbrew.UsersDialect,
				Format: "INSERT INTO site_user (site_id, user_id)" +
					" VALUES ((SELECT site_id FROM site WHERE site_name = {siteName}), (SELECT user_id FROM users WHERE username = {username}))",
				Values: []any{
					sq.StringParam("siteName", request.SiteName),
					sq.StringParam("username", username),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			err = tx.Commit()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
