package nb9

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"runtime/debug"
	"strings"

	"github.com/bokwoon95/nb9/sq"
)

func (nbrew *Notebrew) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scheme := "https://"
	if nbrew.CMSDomain == "localhost" || strings.HasPrefix(nbrew.CMSDomain, "localhost:") {
		scheme = "http://"
	}

	defer func() {
		if v := recover(); v != nil {
			fmt.Println(r.Method + " " + scheme + r.Host + r.URL.RequestURI() + ":\n" + string(debug.Stack()))
		}
	}()

	// Redirect the www subdomain to the bare domain.
	if r.Host == "www."+nbrew.CMSDomain {
		http.Redirect(w, r, scheme+nbrew.CMSDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	// Clean the path and redirect if necessary.
	if r.Method == "GET" {
		cleanedPath := path.Clean(r.URL.Path)
		if cleanedPath != "/" && path.Ext(cleanedPath) == "" {
			cleanedPath += "/"
		}
		if cleanedPath != r.URL.Path {
			cleanedURL := *r.URL
			cleanedURL.Path = cleanedPath
			http.Redirect(w, r, cleanedURL.String(), http.StatusMovedPermanently)
			return
		}
	}
	urlPath := strings.Trim(r.URL.Path, "/")

	// Add request method and url to the logger.
	logger := nbrew.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(
		slog.String("method", r.Method),
		slog.String("url", scheme+r.Host+r.URL.RequestURI()),
	)
	r = r.WithContext(context.WithValue(r.Context(), loggerKey, logger))

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
	w.Header().Add("X-Frame-Options", "DENY")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Add("Permissions-Policy", "geolocation=(), microphone=()")
	w.Header().Add("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Add("Cross-Origin-Embedder-Policy", "require-corp")
	w.Header().Add("Cross-Origin-Resource-Policy", "same-origin")
	if nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:") {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}

	if r.Method == "GET" {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
		err := r.ParseForm()
		if err != nil {
			badRequest(w, r, err)
			return
		}
	}

	// Handle the /users/* route on the CMS domain.
	head, tail, _ := strings.Cut(urlPath, "/")
	if r.Host == nbrew.CMSDomain && head == "users" {
		switch tail {
		case "signup":
			// nbrew.signup(w, r, ip)
		case "login":
			// nbrew.login(w, r, ip)
		case "logout":
			// nbrew.logout(w, r, ip)
		case "resetpassword":
		default:
			notFound(w, r)
		}
		return
	}

	// Handle the /files/* route on the CMS domain.
	if r.Host == nbrew.CMSDomain && head == "files" {
		urlPath := tail
		head, tail, _ := strings.Cut(urlPath, "/")
		if head == "static" {
			if r.Method != "GET" {
				methodNotAllowed(w, r)
				return
			}
			fileType, ok := fileTypes[path.Ext(urlPath)]
			if !ok {
				notFound(w, r)
				return
			}
			file, err := RuntimeFS.Open(urlPath)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			serveFile(w, r, file, fileInfo, fileType, "max-age: 2592000, stale-while-revalidate" /* 30 days */)
			return
		}

		// Figure out the sitePrefix of the site we are serving.
		var sitePrefix string
		if strings.HasPrefix(head, "@") || (strings.Contains(head, ".") && head != "site.json") {
			sitePrefix, urlPath = head, tail
			head, tail, _ = strings.Cut(urlPath, "/")
		}

		// If the users database is present, check if the user is authorized to
		// access the files for this site.
		var username string
		var isAuthorizedForSite bool
		if nbrew.DB != nil {
			authenticationTokenHash := getAuthenticationTokenHash(r)
			if authenticationTokenHash == nil {
				if head == "" {
					http.Redirect(w, r, "/users/login/?401", http.StatusFound)
					return
				}
				notAuthenticated(w, r)
				return
			}
			result, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "SELECT {*}" +
					" FROM authentication" +
					" JOIN users ON users.user_id = authentication.user_id" +
					" WHERE authentication.authentication_token_hash = {authenticationTokenHash}",
				Values: []any{
					sq.BytesParam("authenticationTokenHash", authenticationTokenHash),
				},
			}, func(row *sq.Row) (result struct {
				Username            string
				IsAuthorizedForSite bool
			}) {
				result.Username = row.String("users.username")
				result.IsAuthorizedForSite = row.Bool("EXISTS (SELECT 1"+
					" FROM site"+
					" JOIN site_user ON site_user.site_id = site.site_id"+
					" WHERE site.site_name = {siteName}"+
					" AND site_user.user_id = users.user_id"+
					")",
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
				)
				return result
			})
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					logger.Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				http.SetCookie(w, &http.Cookie{
					Path:   "/",
					Name:   "authentication",
					Value:  "0",
					MaxAge: -1,
				})
				if head == "" {
					http.Redirect(w, r, "/users/login/?401", http.StatusFound)
					return
				}
				notAuthenticated(w, r)
				return
			}
			username = result.Username
			isAuthorizedForSite = result.IsAuthorizedForSite
			logger := logger.With(slog.String("username", username))
			r = r.WithContext(context.WithValue(r.Context(), loggerKey, logger))
		}

		switch head {
		case "", "notes", "pages", "posts", "output", "site.json":
			if nbrew.DB != nil && !isAuthorizedForSite {
				if sitePrefix != "" || urlPath != "" {
					notAuthorized(w, r)
					return
				}
			}
			nbrew.file(w, r, username, sitePrefix, urlPath)
			return
		case "clipboard":
			if nbrew.DB != nil && !isAuthorizedForSite {
				notAuthorized(w, r)
				return
			}
			nbrew.clipboard(w, r, username, sitePrefix, tail)
			return
		}

		switch urlPath {
		case "regenerate":
			if nbrew.DB != nil && !isAuthorizedForSite {
				notAuthorized(w, r)
				return
			}
			nbrew.regenerate(w, r, sitePrefix)
		case "regeneratelist":
			if nbrew.DB != nil && !isAuthorizedForSite {
				notAuthorized(w, r)
				return
			}
			nbrew.regeneratelist(w, r, sitePrefix)
		case "createsite":
			if sitePrefix != "" {
				notFound(w, r)
				return
			}
			nbrew.createsite(w, r, username)
		case "deletesite":
			if sitePrefix != "" {
				notFound(w, r)
				return
			}
			nbrew.deletesite(w, r, username)
		case "createfolder":
			if nbrew.DB != nil && !isAuthorizedForSite {
				notAuthorized(w, r)
				return
			}
			nbrew.createfolder(w, r, username, sitePrefix)
		case "createfile":
			if nbrew.DB != nil && !isAuthorizedForSite {
				notAuthorized(w, r)
				return
			}
			nbrew.createfile(w, r, username, sitePrefix)
		case "delete":
			if nbrew.DB != nil && !isAuthorizedForSite {
				notAuthorized(w, r)
				return
			}
			nbrew.delete(w, r, username, sitePrefix)
		case "search":
			if nbrew.DB != nil && !isAuthorizedForSite {
				notAuthorized(w, r)
				return
			}
			nbrew.search(w, r, username, sitePrefix)
		case "uploadfile":
			if nbrew.DB != nil && !isAuthorizedForSite {
				notAuthorized(w, r)
				return
			}
			nbrew.uploadfile(w, r, username, sitePrefix)
		case "rename":
			if nbrew.DB != nil && !isAuthorizedForSite {
				notAuthorized(w, r)
				return
			}
			nbrew.rename(w, r, username, sitePrefix)
		default:
			notFound(w, r)
		}
		return
	}

	// If we reach here, we are serving generated site content. Only GET
	// requests are allowed.
	if r.Method != "GET" {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Figure out the sitePrefix of the site we have to serve.
	var sitePrefix string
	var subdomain string
	if MatchWildcard(r.Host, "*."+nbrew.ContentDomain) {
		subdomain = strings.TrimSuffix(r.Host, "."+nbrew.ContentDomain)
		if subdomain == "img" {
			// examples:
			// img.nbrew.io/foo/bar.jpg             => sitePrefix: <none>,      urlPath: foo/bar.jpg
			// img.nbrew.io/@username/foo/bar.jpg   => sitePrefix: @username,   urlPath: foo/bar.jpg
			// img.nbrew.io/example.com/foo/bar.jpg => sitePrefix: example.com, urlPath: foo/bar.jpg
			if strings.HasPrefix(head, "@") {
				sitePrefix, urlPath = head, tail
			} else if strings.Contains(head, ".") {
				if tail != "" {
					sitePrefix, urlPath = head, tail
				} else {
					_, ok := fileTypes[path.Ext(head)] // if it's not a file extension, then it's a TLD
					if !ok {
						sitePrefix, urlPath = head, tail
					}
				}
			}
		} else {
			sitePrefix = "@" + subdomain
		}
	} else if r.Host != nbrew.ContentDomain {
		sitePrefix = r.Host
	}

	var filePath string
	var fileType FileType
	ext := path.Ext(urlPath)
	if ext == "" {
		if subdomain == "www" {
			http.Redirect(w, r, scheme+nbrew.ContentDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}
		filePath = path.Join(sitePrefix, "output", urlPath, "index.html")
		fileType.Ext = ".html"
		fileType.ContentType = "text/html; charset=utf-8"
		fileType.IsGzippable = true
	} else {
		if path.Base(urlPath) == "index.html" {
			custom404(w, r, nbrew.FS, sitePrefix)
			return
		}
		filePath = path.Join(sitePrefix, "output", urlPath)
		fileType = fileTypes[ext]
		if fileType == (FileType{}) {
			custom404(w, r, nbrew.FS, sitePrefix)
			return
		}
	}
	file, err := nbrew.FS.Open(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			custom404(w, r, nbrew.FS, sitePrefix)
			return
		}
		logger.Error(err.Error())
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		logger.Error(err.Error())
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	if fileInfo.IsDir() {
		custom404(w, r, nbrew.FS, sitePrefix)
		return
	}
	var cacheControl string
	switch fileType.Ext {
	case ".html":
		cacheControl = "no-cache, must-revalidate"
	case ".eot", ".otf", ".ttf", ".woff", ".woff2":
		cacheControl = "no-cache, stale-while-revalidate, max-age=2592000" /* 30 days */
	case ".jpeg", ".jpg", ".png", ".webp", ".gif":
		var isS3Storage bool
		if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
			_, isS3Storage = remoteFS.Storage.(*S3Storage)
		}
		if nbrew.ImgDomain != "" && isS3Storage {
			cacheControl = "max-age=31536000, immutable"
		} else {
			cacheControl = "no-cache, stale-while-revalidate, max-age=120" /* 2 minutes */
		}
	default:
		cacheControl = "no-cache, stale-while-revalidate, max-age=120" /* 2 minutes */
	}
	serveFile(w, r, file, fileInfo, fileType, cacheControl)
}

func custom404(w http.ResponseWriter, r *http.Request, fsys FS, sitePrefix string) {
	file, err := fsys.WithContext(r.Context()).Open(path.Join(sitePrefix, "output/404/index.html"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
		}
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	if remoteFile, ok := file.(*RemoteFile); ok {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotFound)
		_, err := io.Copy(w, bytes.NewReader(remoteFile.buf.Bytes()))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(w)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, err = io.Copy(gzipWriter, file)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	} else {
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
	}
}

// NOTE: MatchWildcard is copied from github.com/caddyserver/certmagic
//
// MatchWildcard returns true if subject (a candidate DNS name)
// matches wildcard (a reference DNS name), mostly according to
// RFC 6125-compliant wildcard rules. See also RFC 2818 which
// states that IP addresses must match exactly, but this function
// does not attempt to distinguish IP addresses from internal or
// external DNS names that happen to look like IP addresses.
// It uses DNS wildcard matching logic and is case-insensitive.
// https://tools.ietf.org/html/rfc2818#section-3.1
func MatchWildcard(subject, wildcard string) bool {
	// TODO: I'm pretty sure we can reduce allocations by avoiding
	// strings.ToLower and use strings.EqualFold instead. Not sure what the
	// rest of the code is doing though, if you do optimize this function make
	// sure to also test it.
	// TODO: we can also optimize it by implicitly prefixing the wildcard with
	// "*." so that the caller does not have to concatenate "*." with the
	// original string and incur an allocation.
	subject, wildcard = strings.ToLower(subject), strings.ToLower(wildcard)
	if subject == wildcard {
		return true
	}
	if !strings.Contains(wildcard, "*") {
		return false
	}
	labels := strings.Split(subject, ".")
	for i := range labels {
		if labels[i] == "" {
			continue // invalid label
		}
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if candidate == wildcard {
			return true
		}
	}
	return false
}
