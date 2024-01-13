package nb9

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/bokwoon95/nb9/sq"
)

func (nbrew *Notebrew) deletesite(w http.ResponseWriter, r *http.Request, username string) {
	type Request struct {
		SiteName string `json:"siteName,omitempty"`
	}
	type Response struct {
		Status   string `json:"status"`
		SiteName string `json:"siteName,omitempty"`
	}

	validateSiteName := func(siteName string) bool {
		if len(siteName) > 30 {
			return false
		}
		for _, char := range siteName {
			if (char < 'a' && char > 'z') && (char < '0' && char > '9') && char != '-' && char != '.' {
				return false
			}
		}
		return true
	}

	siteIsUser := func(siteName string) (bool, error) {
		if nbrew.UsersDB == nil {
			return false, nil
		}
		exists, err := sq.FetchExists(r.Context(), nbrew.UsersDB, sq.Query{
			Dialect: nbrew.UsersDialect,
			Format:  "SELECT 1 FROM users WHERE username = {siteName}",
			Values: []any{
				sq.StringParam("siteName", siteName),
			},
		})
		if err != nil {
			return false, err
		}
		return exists, nil
	}

	// site join site_owner join users
	getSitePermissions := func(siteName, username string) (siteNotFound, userIsAuthorized bool, err error) {
		userIsAuthorized, err = sq.FetchOne(r.Context(), nbrew.UsersDB, sq.Query{
			Dialect: nbrew.UsersDialect,
			Format: "SELECT {*}" +
				" FROM site" +
				" LEFT JOIN site_user ON site_user.site_id = site.site_id" +
				" LEFT JOIN users ON users.user_id = site_user.user_id" +
				" WHERE site.site_name = {siteName}" +
				" AND users.username = {username}",
			Values: []any{
				sq.StringParam("siteName", siteName),
				sq.StringParam("username", username),
			},
		}, func(row *sq.Row) bool {
			return row.Bool("users.user_id IS NOT NULL")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return true, false, nil
			}
			return false, false, err
		}
		return false, userIsAuthorized, nil
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
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
				"trimPrefix":  strings.TrimPrefix,
				"stylesCSS":   func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS":  func() template.JS { return template.JS(baselineJS) },
				"hasDatabase": func() bool { return nbrew.DB != nil },
				"referer":     func() string { return r.Referer() },
				"username":    func() string { return username },
				"toSitePrefix": func(siteName string) string {
					if strings.Contains(siteName, ".") {
						return siteName
					}
					if siteName != "" {
						return "@" + siteName
					}
					return ""
				},
			}
			tmpl, err := template.New("deletesite.html").Funcs(funcMap).ParseFS(rootFS, "embed/deletesite.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			contentSecurityPolicy(w, "", false)
			executeTemplate(w, r, time.Time{}, tmpl, &response)
		}

		err := r.ParseForm()
		if err != nil {
			badRequest(w, r, err)
			return
		}
		var response Response
		_, err = nbrew.getSession(r, "flash", &response)
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

		response.SiteName = r.Form.Get("name")
		if response.SiteName == "" {
			response.Status = ErrSiteNameNotProvided
			writeResponse(w, r, response)
			return
		}
		valid := validateSiteName(response.SiteName)
		if !valid {
			response.Status = ErrInvalidSiteName
			writeResponse(w, r, response)
			return
		}
		isUser, err := siteIsUser(response.SiteName)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		if isUser {
			response.Status = ErrSiteIsUser
			writeResponse(w, r, response)
			return
		}
		siteNotFound, userIsAuthorized, err := getSitePermissions(response.SiteName, username)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		if siteNotFound {
			response.Status = ErrSiteNotFound
			writeResponse(w, r, response)
			return
		}
		if !userIsAuthorized {
			response.Status = ErrNotAuthorized
			writeResponse(w, r, response)
			return
		}
		response.Status = Success
		writeResponse(w, r, response)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
			if accept == "application/json" {
				w.Header().Set("Content-Type", "application/json")
				b, err := json.Marshal(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				w.Write(b)
				return
			}
			if !response.Status.Success() {
				err := nbrew.setSession(w, r, "flash", &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, nbrew.Scheme+nbrew.AdminDomain+"/admin/deletesite/", http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"status": Error(fmt.Sprintf(`%s Site deleted`, response.Status.Code())),
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, nbrew.Scheme+nbrew.AdminDomain+"/admin/", http.StatusFound)
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

		response := Response{
			SiteName: request.SiteName,
		}
		if response.SiteName == "" {
			response.Status = ErrSiteNameNotProvided
			writeResponse(w, r, response)
			return
		}
		ok := validateSiteName(response.SiteName)
		if !ok {
			response.Status = ErrInvalidSiteName
			writeResponse(w, r, response)
			return
		}
		ok, err := siteIsUser(response.SiteName)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		if ok {
			response.Status = ErrSiteIsUser
			writeResponse(w, r, response)
			return
		}
		siteNotFound, userIsAuthorized, err := getSitePermissions(response.SiteName, username)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		if siteNotFound {
			response.Status = ErrSiteNotFound
			writeResponse(w, r, response)
			return
		}
		if !userIsAuthorized {
			response.Status = ErrNotAuthorized
			writeResponse(w, r, response)
			return
		}

		var sitePrefix string
		if strings.Contains(response.SiteName, ".") {
			sitePrefix = response.SiteName
		} else if response.SiteName != "" {
			sitePrefix = "@" + response.SiteName
		}
		err = RemoveAll(nbrew.FS, sitePrefix)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		if nbrew.DB != nil {
			tx, err := nbrew.DB.Begin()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			defer tx.Rollback()
			_, err = sq.ExecContext(r.Context(), tx, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format: "DELETE FROM site_user WHERE EXISTS (" +
					"SELECT 1" +
					" FROM site" +
					" WHERE site.site_id = site_user.site_id" +
					" AND site.site_name = {siteName}" +
					")",
				Values: []any{
					sq.StringParam("siteName", request.SiteName),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			_, err = sq.ExecContext(r.Context(), tx, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format:  "DELETE FROM site WHERE site_name = {siteName}",
				Values: []any{
					sq.StringParam("siteName", request.SiteName),
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
		response.Status = DeleteSiteSuccess
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
