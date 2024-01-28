package nb9

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bokwoon95/nb9/sq"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"golang.org/x/crypto/blake2b"
)

// Notebrew represents a notebrew instance.
type Notebrew struct {
	// FS is the file system associated with the notebrew instance.
	FS FS

	// UsersDB is the UsersDB associated with the notebrew instance.
	UsersDB *sql.DB

	// UsersDialect is UsersDialect of the database. Only sqlite, postgres and mysql
	// databases are supported.
	UsersDialect string

	// UsersErrorCode translates a database error into an dialect-specific error
	// code. If the error is not a database error or if no underlying
	// implementation is provided, UsersErrorCode should return an empty string.
	UsersErrorCode func(error) string

	CMSDomain string // localhost:6444, example.com

	ContentDomain string // localhost:6444, example.com

	CDNDomain string

	Proxies map[netip.Addr]struct{} // TODO: fill it in in main

	ProxyForwardedIPHeader map[netip.Addr]string // TODO: fill it in in main

	Logger *slog.Logger
}

type contextKey struct{}

var loggerKey = &contextKey{}

func getLogger(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

// TODO: instrument a quick way to toggle dumping setSession/getSession? I used
// to use sq's logging facilities for this, but maybe I just need the json
// payload.
func (nbrew *Notebrew) setSession(w http.ResponseWriter, r *http.Request, name string, value any) error {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(&value)
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	cookie := &http.Cookie{
		Path:     "/",
		Name:     name,
		Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if nbrew.UsersDB == nil {
		cookie.Value = base64.URLEncoding.EncodeToString(buf.Bytes())
	} else {
		var sessionToken [8 + 16]byte
		binary.BigEndian.PutUint64(sessionToken[:8], uint64(time.Now().Unix()))
		_, err := rand.Read(sessionToken[8:])
		if err != nil {
			return fmt.Errorf("reading rand: %w", err)
		}
		var sessionTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(sessionToken[8:])
		copy(sessionTokenHash[:8], sessionToken[:8])
		copy(sessionTokenHash[8:], checksum[:])
		_, err = sq.Exec(r.Context(), nbrew.UsersDB, sq.Query{
			Dialect: nbrew.UsersDialect,
			Format:  "INSERT INTO session (session_token_hash, data) VALUES ({sessionTokenHash}, {data})",
			Values: []any{
				sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
				sq.StringParam("data", strings.TrimSpace(buf.String())),
			},
		})
		if err != nil {
			return fmt.Errorf("saving session: %w", err)
		}
		cookie.Value = strings.TrimLeft(hex.EncodeToString(sessionToken[:]), "0")
	}
	http.SetCookie(w, cookie)
	return nil
}

func (nbrew *Notebrew) getSession(r *http.Request, name string, valuePtr any) (ok bool, err error) {
	cookie, _ := r.Cookie(name)
	if cookie == nil {
		return false, nil
	}
	var dataBytes []byte
	if nbrew.UsersDB == nil {
		dataBytes, err = base64.URLEncoding.DecodeString(cookie.Value)
		if err != nil {
			return false, nil
		}
	} else {
		sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
		if err != nil {
			return false, nil
		}
		var sessionTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(sessionToken[8:])
		copy(sessionTokenHash[:8], sessionToken[:8])
		copy(sessionTokenHash[8:], checksum[:])
		creationTime := time.Unix(int64(binary.BigEndian.Uint64(sessionTokenHash[:8])), 0)
		if time.Now().Sub(creationTime) > 5*time.Minute {
			return false, nil
		}
		dataBytes, err = sq.FetchOne(r.Context(), nbrew.UsersDB, sq.Query{
			Dialect: nbrew.UsersDialect,
			Format:  "SELECT {*} FROM session WHERE session_token_hash = {sessionTokenHash}",
			Values: []any{
				sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
			},
		}, func(row *sq.Row) []byte {
			return row.Bytes("data")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
	}
	err = json.Unmarshal(dataBytes, valuePtr)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (nbrew *Notebrew) clearSession(w http.ResponseWriter, r *http.Request, name string) {
	cookie, _ := r.Cookie(name)
	if cookie == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Path:     "/",
		Name:     name,
		Value:    "0",
		MaxAge:   -1,
		Secure:   nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:"),
		HttpOnly: true,
	})
	if nbrew.UsersDB == nil {
		return
	}
	sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
	if err != nil {
		return
	}
	var sessionTokenHash [8 + blake2b.Size256]byte
	checksum := blake2b.Sum256(sessionToken[8:])
	copy(sessionTokenHash[:8], sessionToken[:8])
	copy(sessionTokenHash[8:], checksum[:])
	_, err = sq.Exec(r.Context(), nbrew.UsersDB, sq.Query{
		Dialect: nbrew.UsersDialect,
		Format:  "DELETE FROM session WHERE session_token_hash = {sessionTokenHash}",
		Values: []any{
			sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
		},
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	}
}

func getAuthenticationTokenHash(r *http.Request) []byte {
	var encodedToken string
	if r.Form.Has("api") {
		encodedToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Notebrew ")
	} else {
		cookie, _ := r.Cookie("authentication")
		if cookie != nil {
			encodedToken = cookie.Value
		}
	}
	if encodedToken == "" {
		return nil
	}
	token, err := hex.DecodeString(fmt.Sprintf("%048s", encodedToken))
	if err != nil {
		return nil
	}
	var tokenHash [8 + blake2b.Size256]byte
	checksum := blake2b.Sum256(token[8:])
	copy(tokenHash[:8], token[:8])
	copy(tokenHash[8:], checksum[:])
	return tokenHash[:]
}

var base32Encoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

var goldmarkMarkdown = func() goldmark.Markdown {
	md := goldmark.New()
	md.Parser().AddOptions(parser.WithAttribute())
	extension.Table.Extend(md)
	return md
}()

func stripMarkdownStyles(src []byte) string {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var node ast.Node
	nodes := []ast.Node{
		goldmarkMarkdown.Parser().Parse(text.NewReader(src)),
	}
	for len(nodes) > 0 {
		node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
		if node == nil {
			continue
		}
		switch node := node.(type) {
		case *ast.Text:
			buf.Write(node.Text(src))
		}
		nodes = append(nodes, node.NextSibling(), node.FirstChild())
	}
	// Manually escape backslashes (goldmark may be able to do this,
	// investigate).
	var b strings.Builder
	output := buf.Bytes()
	// Jump to the location of each backslash found in the output.
	for i := bytes.IndexByte(output, '\\'); i >= 0; i = bytes.IndexByte(output, '\\') {
		b.Write(output[:i])
		char, width := utf8.DecodeRune(output[i+1:])
		if char != utf8.RuneError {
			b.WriteRune(char)
		}
		output = output[i+1+width:]
	}
	b.Write(output)
	return b.String()
}

var isForbiddenChar = [...]bool{
	' ': true, '!': true, '"': true, '#': true, '$': true, '%': true, '&': true, '\'': true,
	'(': true, ')': true, '*': true, '+': true, ',': true, '/': true, ':': true, ';': true,
	'<': true, '>': true, '=': true, '?': true, '[': true, ']': true, '\\': true, '^': true,
	'`': true, '{': true, '}': true, '|': true, '~': true,
}

func urlSafe(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, char := range s {
		if utf8.RuneCountInString(b.String()) >= 80 {
			break
		}
		if char == ' ' {
			b.WriteRune('-')
			continue
		}
		if char == '-' || (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') {
			b.WriteRune(char)
			continue
		}
		if char >= 'A' && char <= 'Z' {
			b.WriteRune(unicode.ToLower(char))
			continue
		}
		n := int(char)
		if n < len(isForbiddenChar) && isForbiddenChar[n] {
			continue
		}
		b.WriteRune(char)
	}
	return strings.Trim(b.String(), ".")
}

func IsCommonPassword(password []byte) bool {
	hash := blake2b.Sum256(password)
	encodedHash := hex.EncodeToString(hash[:])
	_, ok := commonPasswordHashes[encodedHash]
	return ok
}

func (nbrew *Notebrew) realClientIP(r *http.Request) string {
	// Reference: https://adam-p.ca/blog/2022/03/x-forwarded-for/
	// proxies.json example:
	// {proxyIPs: ["<ip>", "<ip>", "<ip>"], forwardedIPHeaders: {"<ip>": "X-Real-IP", "<ip>": "CF-Connecting-IP"}}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	remoteAddr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	// If we don't have any proxy servers configured (i.e. we are directly
	// connected to the internet), treat remoteAddr as the real client IP.
	if len(nbrew.ProxyForwardedIPHeader) == 0 && len(nbrew.Proxies) == 0 {
		return remoteAddr.String()
	}
	// If remoteAddr is trusted to populate a known header with the real client
	// IP, look in that header.
	if trustedHeader, ok := nbrew.ProxyForwardedIPHeader[remoteAddr]; ok {
		ipAddr, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(trustedHeader)))
		if err != nil {
			return ""
		}
		return ipAddr.String()
	}
	// Check X-Forwarded-For header only if remoteAddr is the IP of a proxy
	// server.
	_, ok := nbrew.Proxies[remoteAddr]
	if !ok {
		return remoteAddr.String()
	}
	// Loop over all IP addresses in X-Forwarded-For headers from right to
	// left. We want to rightmost IP address that isn't a proxy server's IP
	// address.
	values := r.Header.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		ips := strings.Split(values[i], ",")
		for j := len(ips) - 1; j >= 0; j-- {
			ip := ips[j]
			ipAddr, err := netip.ParseAddr(strings.TrimSpace(ip))
			if err != nil {
				continue
			}
			_, ok := nbrew.Proxies[ipAddr]
			if ok {
				continue
			}
			return ipAddr.String()
		}
	}
	return ""
}

var gzipReaderPool = sync.Pool{}

var gzipWriterPool = sync.Pool{
	New: func() any {
		// Use compression level 4 for best balance between space and
		// performance.
		// https://blog.klauspost.com/gzip-performance-for-go-webservers/
		gzipWriter, _ := gzip.NewWriterLevel(nil, 4)
		return gzipWriter
	},
}

var hashPool = sync.Pool{
	New: func() any {
		hash, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return hash
	},
}

var readerPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 512)
	},
}

func executeTemplate(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data any) {
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

	multiWriter := io.MultiWriter(buf, hasher)
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(multiWriter)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()

	err := tmpl.Execute(gzipWriter, data)
	if err != nil {
		getLogger(r.Context()).Error(err.Error(), slog.String("data", fmt.Sprintf("%#v", data)))
		internalServerError(w, r, err)
		return
	}
	err = gzipWriter.Close()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}

	var b [blake2b.Size256]byte
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(buf.Bytes()))
}

func (nbrew *Notebrew) contentSite(sitePrefix string) string {
	if strings.Contains(sitePrefix, ".") {
		return "https://" + sitePrefix
	}
	if nbrew.CMSDomain == "localhost" || strings.HasPrefix(nbrew.CMSDomain, "localhost:") {
		if sitePrefix != "" {
			return "http://" + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.CMSDomain
		}
		return "http://" + nbrew.CMSDomain
	}
	if sitePrefix != "" {
		return "https://" + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.ContentDomain
	}
	return "https://" + nbrew.ContentDomain
}

func getReferer(r *http.Request) string {
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
	//
	// "The Referer header can contain an origin, path, and querystring, and
	// may not contain URL fragments (i.e. #section) or username:password
	// information."
	referer := r.Referer()
	uri := *r.URL
	if r.Host == "localhost" || strings.HasPrefix(r.Host, "localhost:") {
		uri.Scheme = "http"
	} else {
		uri.Scheme = "https"
	}
	uri.Host = r.Host
	uri.Fragment = ""
	uri.User = nil
	// If the referer is same as the current page, return an empty string so
	// that the user doesn't keep pressing back to the same page.
	if referer == uri.String() {
		return ""
	}
	return referer
}

var errorTemplate = template.Must(template.
	New("error.html").
	Funcs(map[string]any{
		"safeHTML": func(v any) template.HTML {
			if str, ok := v.(string); ok {
				return template.HTML(str)
			}
			return ""
		},
	}).
	ParseFS(RuntimeFS, "embed/error.html"),
)

func fileSizeToString(size int64) string {
	// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
	if size < 0 {
		return ""
	}
	const unit = 1000
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "kMGTPE"[exp])
}

func badRequest(w http.ResponseWriter, r *http.Request, serverErr error) {
	var msg string
	var maxBytesErr *http.MaxBytesError
	if errors.As(serverErr, &maxBytesErr) {
		msg = "the data you are sending is too big (max " + fileSizeToString(maxBytesErr.Limit) + ")"
	} else {
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType == "application/json" {
			if serverErr == io.EOF {
				msg = "missing JSON body"
			} else if serverErr == io.ErrUnexpectedEOF {
				msg = "malformed JSON"
			} else {
				msg = serverErr.Error()
			}
		} else {
			msg = serverErr.Error()
		}
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		serverErr = encoder.Encode(map[string]any{
			"status": "BadRequest: " + msg,
		})
		if serverErr != nil {
			getLogger(r.Context()).Error(serverErr.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Title":    `400 bad request`,
		"Headline": "400 bad request",
		"Byline":   msg,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "BadRequest: "+msg, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusBadRequest)
	buf.WriteTo(w)
}

func notAuthenticated(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": "NotAuthenticated",
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var query string
	if r.Method == "GET" {
		if r.URL.RawQuery != "" {
			query = "?redirect=" + url.QueryEscape(r.URL.Path+"?"+r.URL.RawQuery)
		} else {
			query = "?redirect=" + url.QueryEscape(r.URL.Path)
		}
	}
	err := errorTemplate.Execute(buf, map[string]any{
		"Title":    `401 unauthorized`,
		"Headline": "401 unauthorized",
		"Byline":   fmt.Sprintf(`You are not authenticated, please <a href="/users/login/%s">log in</a>.`, query),
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotAuthenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusUnauthorized)
	buf.WriteTo(w)
}

func notAuthorized(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": "NotAuthorized",
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  getReferer(r),
		"Title":    "403 forbidden",
		"Headline": "403 forbidden",
		"Byline":   "You do not have permission to view this page (try logging in to a different account).",
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotAuthorized", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusForbidden)
	buf.WriteTo(w)
}

func notFound(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": "NotFound",
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  getReferer(r),
		"Title":    "404 not found",
		"Headline": "404 not found",
		"Byline":   "The page you are looking for does not exist.",
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotFound", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusNotFound)
	buf.WriteTo(w)
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": "MethodNotAllowed: " + r.Method,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  getReferer(r),
		"Title":    "405 method not allowed",
		"Headline": "405 method not allowed: " + r.Method,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotFound", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusMethodNotAllowed)
	buf.WriteTo(w)
}

func unsupportedContentType(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	var msg string
	if contentType == "" {
		msg = "missing Content-Type"
	} else {
		msg = "unsupported Content-Type: " + contentType
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": "UnsupportedMediaType " + msg,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  getReferer(r),
		"Title":    "415 unsupported media type",
		"Headline": msg,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "UnsupportedMediaType "+msg, http.StatusUnsupportedMediaType)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusUnsupportedMediaType)
	buf.WriteTo(w)
}

func internalServerError(w http.ResponseWriter, r *http.Request, serverErr error) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": "ServerError: " + serverErr.Error(),
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var data map[string]any
	if errors.Is(serverErr, context.DeadlineExceeded) {
		data = map[string]any{
			"Referer":  getReferer(r),
			"Title":    "deadline exceeded",
			"Headline": "The server took too long to respond.",
		}
	} else {
		data = map[string]any{
			"Referer":  r.Referer(),
			"Title":    "500 internal server error",
			"Headline": "500 internal server error",
			"Byline":   "There's a bug with notebrew.",
			"Details":  serverErr.Error(),
		}
	}
	err := errorTemplate.Execute(buf, data)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "ServerError", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.WriteHeader(http.StatusInternalServerError)
	buf.WriteTo(w)
}

func serveFile(w http.ResponseWriter, r *http.Request, file fs.File, fileInfo fs.FileInfo, fileType FileType, cacheControl string) {
	// .jpeg .jpg .png .webp .gif .woff .woff2
	if !fileType.IsGzippable {
		if fileSeeker, ok := file.(io.ReadSeeker); ok {
			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()
			_, err := io.Copy(hasher, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			_, err = fileSeeker.Seek(0, io.SeekStart)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var b [blake2b.Size256]byte
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", cacheControl)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
			http.ServeContent(w, r, "", fileInfo.ModTime(), fileSeeker)
			return
		}

		if fileInfo.Size() <= 1<<20 /* 1 MB */ {
			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()
			var buf *bytes.Buffer
			if fileInfo.Size() > maxPoolableBufferCapacity {
				buf = bytes.NewBuffer(make([]byte, 0, fileInfo.Size()))
			} else {
				buf = bufPool.Get().(*bytes.Buffer)
				defer func() {
					buf.Reset()
					bufPool.Put(buf)
				}()
			}
			multiWriter := io.MultiWriter(hasher, buf)
			_, err := io.Copy(multiWriter, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var b [blake2b.Size256]byte
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", cacheControl)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
			http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
			return
		}

		w.Header().Set("Content-Type", fileType.ContentType)
		w.Header().Set("Cache-Control", cacheControl)
		_, err := io.Copy(w, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}

	// .html .css .js .md .txt .svg .ico .eot .otf .ttf .atom .webmanifest

	if remoteFile, ok := file.(*RemoteFile); ok {
		// If file is a RemoteFile and is not fulltext indexed, its contents
		// are already gzipped. We can reach directly into its buffer and skip
		// the gzipping step.
		if !remoteFile.isFulltextIndexed {
			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()
			_, err := hasher.Write(remoteFile.buf.Bytes())
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var b [blake2b.Size256]byte
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", cacheControl)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
			http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(remoteFile.buf.Bytes()))
			return
		}
	}

	if fileInfo.Size() <= 1<<20 /* 1 MB */ {
		hasher := hashPool.Get().(hash.Hash)
		defer func() {
			hasher.Reset()
			hashPool.Put(hasher)
		}()
		var buf *bytes.Buffer
		// gzip will at least halve the size of what needs to be buffered
		gzippedSize := fileInfo.Size() >> 1
		if gzippedSize > maxPoolableBufferCapacity {
			buf = bytes.NewBuffer(make([]byte, 0, fileInfo.Size()))
		} else {
			buf = bufPool.Get().(*bytes.Buffer)
			defer func() {
				buf.Reset()
				bufPool.Put(buf)
			}()
		}
		multiWriter := io.MultiWriter(buf, hasher)
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(multiWriter)
		defer func() {
			gzipWriter.Reset(io.Discard)
			gzipWriterPool.Put(gzipWriter)
		}()
		_, err := io.Copy(gzipWriter, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		var b [blake2b.Size256]byte
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", fileType.ContentType)
		w.Header().Set("Cache-Control", cacheControl)
		w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
		http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
		return
	}

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", fileType.ContentType)
	w.Header().Set("Cache-Control", cacheControl)
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(w)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	_, err := io.Copy(gzipWriter, file)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	} else {
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
	}
}

type NullString struct {
	String string `json:"string"`
	Valid  bool   `json:"valid"`
}
