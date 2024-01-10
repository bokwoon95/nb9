package nb9

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
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
		SiteName string `json:"siteName,omitempty"`
	}
	type Response struct {
		Status    string     `json:"status"`
		SiteName  string     `json:"siteName,omitempty"`
		SiteNames []string   `json:"siteNames,omitempty"`
		Errors    url.Values `json:"errors,omitempty"`
	}
	// TODO: don't limit maxSites if user is a owner of the main site.
	const maxSites = 3

	getSiteNames := func(username string) ([]string, error) {
		return sq.FetchAll(r.Context(), nbrew.UsersDB, sq.Query{
			Dialect: nbrew.UsersDialect,
			Format: "SELECT {*}" +
				" FROM site" +
				" JOIN site_owner ON site_owner.site_id = site.site_id" +
				" JOIN users ON users.user_id = site_owner.user_id" +
				" WHERE users.username = {username}" +
				" AND site.site_name <> ''",
			Values: []any{
				sq.StringParam("username", username),
			},
		}, func(row *sq.Row) string {
			return row.String("site.site_name")
		})
	}

	switch r.Method {
	case "GET":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
			if accept == "application/json" {
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
				"stylesCSS":  func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS": func() template.JS { return template.JS(baselineJS) },
				"referer":    func() string { return r.Referer() },
				"username":   func() string { return username },
				"maxSites":   func() int { return maxSites },
				"toSitePrefix": func(s string) string {
					if strings.Contains(s, ".") {
						return s
					}
					if s != "" {
						return "@" + s
					}
					return s
				},
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
			internalServerError(w, r, err)
			return
		}
		nbrew.clearSession(w, r, "flash")
		if response.Status != "" {
			writeResponse(w, r, response)
			return
		}
		response.SiteNames, err = getSiteNames(username)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		if len(response.SiteNames) >= maxSites {
			response.Status = "MaxSitesReached"
			writeResponse(w, r, response)
			return
		}
		response.Status = "Success"
		writeResponse(w, r, response)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
			if accept == "application/json" {
				w.Header().Set("Content-Type", "application/json")
				encoder := json.NewEncoder(w)
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			if !strings.HasSuffix(response.Status, "Success") {
				err := nbrew.setSession(w, r, "flash", &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/admin/createsite/", http.StatusFound)
				return
			}
			var sitePrefix string
			if strings.Contains(response.SiteName, ".") {
				sitePrefix = response.SiteName
			} else if response.SiteName != "" {
				sitePrefix = "@" + response.SiteName
			}
			// TODO: how do we differentiate between a Status string
			// (programatic comparison), an alert string (can be success or
			// error) and a field validation error string?
			err := nbrew.setSession(w, r, "flash", map[string]string{
				"Status": fmt.Sprintf(
					`%s Site created: <a href="%s" class="linktext">%s</a>`,
					response.Status,
					"/"+path.Join("admin", sitePrefix)+"/",
					response.SiteName,
				),
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/admin/", http.StatusFound)
		}

		var request Request
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
				err := r.ParseMultipartForm(2 << 20 /* 2MB */)
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
			SiteName: request.SiteName,
			Errors:   url.Values{},
		}
		response.SiteNames, err = getSiteNames(username)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		// TODO: check if user is owner of the main site first.
		if len(response.SiteNames) >= maxSites {
			response.Status = "MaxSitesReached"
			writeResponse(w, r, response)
			return
		}

		if response.SiteName == "" {
			response.Errors["siteName"] = append(response.Errors["siteName"], "required")
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
				response.Errors["siteName"] = append(response.Errors["siteName"], "only lowercase letters, numbers and hyphen allowed")
			}
			if len(response.SiteName) > 30 {
				response.Errors["siteName"] = append(response.Errors["siteName"], "cannot exceed 30 characters")
			}
		}
		var sitePrefix string
		if strings.Contains(response.SiteName, ".") {
			sitePrefix = response.SiteName
		} else if response.SiteName != "" {
			sitePrefix = "@" + response.SiteName
		}
		if response.SiteName == "www" || response.SiteName == "cdn" {
			response.Errors["siteName"] = append(response.Errors["siteName"], "unavailable")
		} else if len(response.Errors["siteName"]) == 0 {
			_, err := fs.Stat(nbrew.FS, sitePrefix)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
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
					response.Errors["siteName"] = append(response.Errors["siteName"], "unavailable")
				}
			} else {
				response.Errors["siteName"] = append(response.Errors["siteName"], "unavailable")
			}
		}
		if len(response.Errors) > 0 {
			response.Status = "ValidationFailed"
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
			"system",
		}
		for _, dir := range dirs {
			err = nbrew.FS.Mkdir(path.Join(sitePrefix, dir), 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		// TODO: copy over index.html, post.html and postlist.html
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
				Format: "INSERT INTO site (site_id, site_name) VALUES ({siteID}, {siteName})",
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
		response.Status = "CreateSiteSuccess"
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
