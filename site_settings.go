package nb9

import "net/http"

func (nbrew *Notebrew) siteSettings(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	// /files/@bokwoon/settings.json
	// /files/posts/settings.json
}
