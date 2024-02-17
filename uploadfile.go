package nb9

import (
	"net/http"
	"path"
)

func (nbrew *Notebrew) uploadfile(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	if r.Method != "POST" {
		methodNotAllowed(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 25<<20 /* 25 MB */)
	referer := r.Referer()
	if referer == "" {
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
		return
	}
}
