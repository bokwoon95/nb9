package nb9

import (
	"encoding/json"
	"net/http"
	"path"
	"strings"

	"github.com/bokwoon95/nb9/sq"
	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) regenerate(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	type Response struct {
		TemplateErrors []string `json:"templateErrors,omitempty"`
	}
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
		err := nbrew.setSession(w, r, "flash", map[string]any{
			"postRedirectGet": map[string]any{
				"from":           "regenerate",
				"templateErrors": response.TemplateErrors,
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
	}

	if r.Method != "POST" {
		methodNotAllowed(w, r)
		return
	}
	siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.CDNDomain)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	markdown := goldmark.New(
		goldmark.WithParserOptions(parser.WithAttribute()),
		goldmark.WithExtensions(
			extension.Table,
			highlighting.NewHighlighting(highlighting.WithStyle(siteGen.Site.CodeStyle)),
		),
		goldmark.WithRendererOptions(goldmarkhtml.WithUnsafe()),
	)
	if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
		var response Response
		g1, ctx1 := errgroup.WithContext(r.Context())
		g1.Go(func() error {
			type File struct {
				FilePath string
				IsDir    bool
				Text     string
			}
			cursor, err := sq.FetchCursor(ctx1, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE file_path LIKE {pattern} ESCAPE '\\'" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.html'" +
					" ORDER BY file_path",
				Values: []any{
					sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(path.Join(sitePrefix, "pages")+"/%")),
				},
			}, func(row *sq.Row) File {
				return File{
					FilePath: row.String("file_path"),
					Text:     row.String("text"),
				}
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			g2, ctx2 := errgroup.WithContext(ctx1)
			for cursor.Next() {
				file, err := cursor.Result()
				if err != nil {
					return err
				}
				if sitePrefix != "" {
					file.FilePath = strings.TrimPrefix(file.FilePath, sitePrefix+"/")
				}
				g2.Go(func() error {
					return siteGen.GeneratePage(ctx2, file.FilePath, file.Text, markdown)
				})
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
			err = g2.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		g1.Go(func() error {
			// generate posts
			return nil
		})
		writeResponse(w, r, response)
		return
	}
}
