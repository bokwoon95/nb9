package nb9

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/bokwoon95/nb9/sq"
)

func (nbrew *Notebrew) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scheme := "https://"
	if nbrew.CMSDomain == "localhost" || strings.HasPrefix(nbrew.CMSDomain, "localhost:") {
		scheme = "http://"
	}

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
	w.Header().Add("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
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
		if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
			sitePrefix, urlPath = head, tail
			head, tail, _ = strings.Cut(urlPath, "/")
		}

		// If the users database is present, check if the user is authorized to
		// access the files for this site.
		var username string
		if nbrew.UsersDB != nil {
			authenticationTokenHash := getAuthenticationTokenHash(r)
			if authenticationTokenHash == nil {
				if head == "" {
					http.Redirect(w, r, "/users/login/?401", http.StatusFound)
					return
				}
				notAuthenticated(w, r)
				return
			}
			result, err := sq.FetchOne(r.Context(), nbrew.UsersDB, sq.Query{
				Dialect: nbrew.UsersDialect,
				Format: "SELECT {*}" +
					" FROM authentication" +
					" JOIN users ON users.user_id = authentication.user_id" +
					" WHERE authentication.authentication_token_hash = {authenticationTokenHash}",
				Values: []any{
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
					sq.BytesParam("authenticationTokenHash", authenticationTokenHash),
				},
			}, func(row *sq.Row) (result struct {
				Username     string
				IsAuthorized bool
			}) {
				result.Username = row.String("users.username")
				result.IsAuthorized = row.Bool("EXISTS (SELECT 1" +
					" FROM site" +
					" JOIN site_user ON site_user.site_id = site.site_id" +
					" WHERE site.site_name = {siteName}" +
					" AND site_user.user_id = users.user_id" +
					")")
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
			logger := logger.With(slog.String("username", username))
			r = r.WithContext(context.WithValue(r.Context(), loggerKey, logger))
			if !result.IsAuthorized {
				if sitePrefix != "" {
					notAuthorized(w, r)
					return
				}
				// If the current sitePrefix is empty, the user needs access to
				// the following file paths unconditionally:
				//
				// 1. <empty> (needed to switch between their sites)
				//
				// 2. createsite (needed to create a new site)
				//
				// 3. deletesite (needed to delete their sites)
				//
				// If not any of the three, then notAuthorized.
				if urlPath != "" && urlPath != "createsite" && urlPath != "deletesite" {
					notAuthorized(w, r)
					return
				}
			}
		}

		if head == "" || head == "notes" || head == "pages" || head == "posts" || head == "output" {
			nbrew.files(w, r, username, sitePrefix, urlPath)
			return
		}

		if head == "clipboard" {
			nbrew.clipboard(w, r, username, sitePrefix, tail)
			return
		}

		switch urlPath {
		case "regenerate":
			nbrew.regenerate(w, r, sitePrefix)
		case "regeneratelist":
			nbrew.regeneratelist(w, r, sitePrefix)
		case "createsite":
			nbrew.createsite(w, r, username)
		case "deletesite":
			nbrew.deletesite(w, r, username)
		case "createfolder":
			nbrew.createfolder(w, r, username, sitePrefix)
		case "createfile":
			nbrew.createfile(w, r, username, sitePrefix)
		case "delete":
			nbrew.delete(w, r, username, sitePrefix)
		case "search":
			nbrew.search(w, r, username, sitePrefix)
		case "rename":
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
		if subdomain == "cdn" || subdomain == "www" {
			// examples:
			// cdn.nbrew.io/foo/bar.jpg             => sitePrefix: <none>,      urlPath: foo/bar.jpg
			// cdn.nbrew.io/@username/foo/bar.jpg   => sitePrefix: @username,   urlPath: foo/bar.jpg
			// cdn.nbrew.io/example.com/foo/bar.jpg => sitePrefix: example.com, urlPath: foo/bar.jpg
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
			if sitePrefix != "" {
				// www subdomain never serves page data for other sites.
				nbrew.site404(w, r, sitePrefix)
				return
			}
			// Redirect the www subdomain to the bare domain.
			http.Redirect(w, r, scheme+nbrew.ContentDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}
		filePath = path.Join(sitePrefix, "output", urlPath, "index.html")
		fileType.Ext = ".html"
		fileType.ContentType = "text/html; charset=utf-8"
		fileType.IsGzippable = true
	} else {
		if path.Base(urlPath) == "index.html" {
			nbrew.site404(w, r, sitePrefix)
			return
		}
		filePath = path.Join(sitePrefix, "output", urlPath)
		fileType = fileTypes[ext]
		if fileType == (FileType{}) {
			nbrew.site404(w, r, sitePrefix)
			return
		}
	}
	file, err := nbrew.FS.Open(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			nbrew.site404(w, r, sitePrefix)
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
		nbrew.site404(w, r, sitePrefix)
		return
	}
	var cacheControl string
	switch fileType.Ext {
	case ".html":
		cacheControl = "no-cache, must-revalidate"
	case ".eot", ".otf", ".ttf", ".woff", ".woff2":
		cacheControl = "no-cache, stale-while-revalidate, max-age=2592000" /* 30 days */
	default:
		cacheControl = "no-cache, stale-while-revalidate, max-age=120" /* 2 minutes */
	}
	serveFile(w, r, file, fileInfo, fileType, cacheControl)
}

// site404 is a 404 handler that will use the site's 404 page if present,
// otherwise it falls back to http.Error().
//
// We fall back to http.Error() instead of notFound() because notFound()
// depends on CSS/JS files hosted on the CMS domain and we don't want that
// dependency.
func (nbrew *Notebrew) site404(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	// Check if the user's custom 404 page is available.
	file, err := nbrew.FS.Open(path.Join(sitePrefix, "output/404/index.html"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
		}
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	fileInfo, err := file.Stat()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()

	hasher := hashPool.Get().(hash.Hash)
	defer func() {
		hasher.Reset()
		hashPool.Put(hasher)
	}()

	// TODO: rewrite this to no longer need bufio.Reader because whether a file
	// is gzipped is an implementation detail of the underlying filesystem.
	reader := readerPool.Get().(*bufio.Reader)
	defer func() {
		reader.Reset(file)
		readerPool.Put(reader)
	}()

	// TODO: instead of peeking to check if the file is gzipped, type assert it
	// to a *RemoteFile and check its isFulltextIndexed field (must be false)
	// to see whether its buf is gzipped.
	//
	// Peek the first 512 bytes to check if 404/index.html is gzipped and
	// write it into the buffer + ETag hasher accordingly. The buffer
	// always receives gzipped data, the only difference is whether the
	// data has been pre-gzipped or not.
	b, err := reader.Peek(512)
	if err != nil && err != io.EOF {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	// NOTE: do we want to calculate ETags for 404 pages? Do we want to cache
	// the 404 response? Are we expecting users to hit 404 pages often?
	contentType := http.DetectContentType(b)
	multiWriter := io.MultiWriter(buf, hasher)
	if contentType == "application/x-gzip" || contentType == "application/gzip" {
		_, err := io.Copy(multiWriter, reader)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
	} else {
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(multiWriter)
		defer func() {
			gzipWriter.Reset(io.Discard)
			gzipWriterPool.Put(gzipWriter)
		}()
		_, err := io.Copy(gzipWriter, reader)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
	}

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
	w.WriteHeader(http.StatusNotFound)
	http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
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
