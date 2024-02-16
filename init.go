package nb9

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"io"
	"io/fs"

	"golang.org/x/crypto/blake2b"
)

//go:embed embed static
var embedFS embed.FS

var RuntimeFS fs.FS = embedFS

var (
	commonPasswordHashes         = make(map[string]struct{})
	stylesCSS                    string
	baselineJS                   string
	contentSecurityPolicy        string
	contentSecurityPolicyCaptcha string
)

func init() {
	// top-10000-passwords.txt
	file, err := embedFS.Open("embed/top-10000-passwords.txt")
	if err != nil {
		return
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	done := false
	for {
		if done {
			break
		}
		line, err := reader.ReadBytes('\n')
		done = err == io.EOF
		if err != nil && !done {
			panic(err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		hash := blake2b.Sum256([]byte(line))
		encodedHash := hex.EncodeToString(hash[:])
		commonPasswordHashes[encodedHash] = struct{}{}
	}
	// styles.css
	b, err := fs.ReadFile(embedFS, "static/styles.css")
	if err != nil {
		return
	}
	hash := sha256.Sum256(b)
	stylesCSS = string(b)
	// baseline.js
	b, err = fs.ReadFile(embedFS, "static/baseline.js")
	if err != nil {
		return
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	hash = sha256.Sum256(b)
	baselineJS = string(b)
	baselineJSHash := "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
	// contentSecurityPolicy
	contentSecurityPolicy = "default-src 'none';" +
		" script-src 'self' 'unsafe-hashes' " + baselineJSHash + ";" +
		" connect-src 'self';" +
		" img-src 'self' data:;" +
		" style-src 'self' 'unsafe-inline';" +
		" base-uri 'self';" +
		" form-action 'self';" +
		" manifest-src 'self';"
	// contentSecurityPolicyCaptcha
	contentSecurityPolicyCaptcha = "default-src 'none';" +
		" script-src 'self' 'unsafe-hashes' " + baselineJSHash + " https://hcaptcha.com https://*.hcaptcha.com;" +
		" connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com;" +
		" img-src 'self' data:;" +
		" style-src 'self' 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com;" +
		" base-uri 'self';" +
		" form-action 'self';" +
		" manifest-src 'self';" +
		" frame-src https://hcaptcha.com https://*.hcaptcha.com;"
}
