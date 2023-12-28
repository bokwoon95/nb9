package nb9

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/template/parse"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/nb9/sq"
	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"
	"golang.org/x/sync/errgroup"
)

type Site struct {
	Title      string
	Favicon    string
	Lang       string
	Categories []string
}

type SiteGenerator struct {
	domain               string
	fsys                 FS
	sitePrefix           string
	site                 Site
	markdown             goldmark.Markdown
	mu                   sync.Mutex
	templateCache        map[string]*template.Template
	templateInProgress   map[string]chan struct{}
	post                 *template.Template
	postErr              error
	postOnce             sync.Once
	postList             *template.Template
	postListErr          error
	postListOnce         sync.Once
	gzipGeneratedContent bool
	postsPerPage         map[string]int // default 100
}

type SiteGeneratorConfig struct {
	ContentDomain        string
	FS                   FS
	SitePrefix           string
	Title                string
	Favicon              string
	Lang                 string
	CodeStyle            string
	GzipGeneratedContent bool
	PostPerPage          map[string]int
}

func NewSiteGenerator(config SiteGeneratorConfig) (*SiteGenerator, error) {
	if config.Favicon == "" {
		config.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>☕</text></svg>"
	} else {
		char, size := utf8.DecodeRuneInString(config.Favicon)
		if size == len(config.Favicon) {
			config.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + string(char) + "</text></svg>"
		}
	}
	if config.Title == "" {
		config.Title = "My blog"
	}
	if config.Lang == "" {
		config.Lang = "en"
	}
	if config.CodeStyle == "" {
		config.CodeStyle = "dracula"
	}
	if config.ContentDomain == "" {
		return nil, fmt.Errorf("ContentDomain cannot be empty")
	}
	var domain string
	if strings.Contains(config.SitePrefix, ".") {
		domain = config.SitePrefix
	} else if config.SitePrefix != "" {
		domain = config.SitePrefix + "." + config.ContentDomain
	} else {
		domain = config.ContentDomain
	}
	siteGen := &SiteGenerator{
		domain:     domain,
		fsys:       config.FS,
		sitePrefix: config.SitePrefix,
		site: Site{
			Title:   config.Title,
			Favicon: config.Favicon,
			Lang:    config.Lang,
		},
		markdown: goldmark.New(
			goldmark.WithParserOptions(parser.WithAttribute()),
			goldmark.WithExtensions(
				extension.Table,
				highlighting.NewHighlighting(highlighting.WithStyle(config.CodeStyle)),
			),
			goldmark.WithRendererOptions(goldmarkhtml.WithUnsafe()),
		),
		mu:                   sync.Mutex{},
		templateCache:        make(map[string]*template.Template),
		templateInProgress:   make(map[string]chan struct{}),
		gzipGeneratedContent: config.GzipGeneratedContent,
	}
	if remoteFS, ok := siteGen.fsys.(*RemoteFS); ok {
		categories, err := sq.FetchAll(remoteFS.ctx, remoteFS.filesDB, sq.Query{
			Dialect: remoteFS.filesDialect,
			Format:  "SELECT {*} FROM files WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {postsDir}) AND is_dir ORDER BY file_path",
			Values: []any{
				sq.StringParam("postsDir", path.Join(siteGen.sitePrefix, "posts")),
			},
		}, func(row *sq.Row) string {
			return path.Base(row.String("file_path"))
		})
		if err != nil {
			return nil, err
		}
		siteGen.site.Categories = categories
	} else {
		dirEntries, err := siteGen.fsys.ReadDir(path.Join(siteGen.sitePrefix, "posts"))
		if err != nil {
			return nil, err
		}
		for _, dirEntry := range dirEntries {
			if dirEntry.IsDir() {
				siteGen.site.Categories = append(siteGen.site.Categories, dirEntry.Name())
			}
		}
	}
	return siteGen, nil
}

type Page struct {
	Parent string
	Name   string
	Title  string
}

type Image struct {
	Parent string
	Name   string
}

type PageData struct {
	Site             Site
	Parent           string
	Name             string
	ChildPages       []Page
	Markdown         map[string]template.HTML
	Images           []Image
	ModificationTime time.Time
}

// GeneratePage(file, childPages)
// GeneratePost(file)
// GeneratePostList(files)
// TODO: figure out how to make GeneratePage and GeneratePost/GeneratePostList
// workable using a single walk of the directory.
// GeneratePage(ctx context.Context, text string, pageData PageData) // Parent and Name *must* be filled in.
func (siteGen *SiteGenerator) GeneratePage(ctx context.Context, name string, file fs.File) error {
	var urlPath string
	if name != "index.html" {
		urlPath = strings.TrimSuffix(name, path.Ext(name))
	}
	outputDir := path.Join(siteGen.sitePrefix, "output", urlPath)
	pageData := PageData{
		Site:   siteGen.site,
		Parent: path.Dir(urlPath),
		Name:   path.Base(urlPath),
	}
	// path.Dir converts empty strings to ".", but we prefer an empty string so
	// convert it back.
	if pageData.Parent == "." {
		pageData.Parent = ""
	}
	g1, ctx1 := errgroup.WithContext(ctx)

	// Prepare the page template.
	var tmpl *template.Template
	g1.Go(func() error {
		fileInfo, err := file.Stat()
		if err != nil {
			return err
		}
		if fileInfo.IsDir() {
			return fmt.Errorf("%s is a folder", name)
		}
		var b strings.Builder
		b.Grow(int(fileInfo.Size()))
		_, err = io.Copy(&b, file)
		if err != nil {
			return err
		}
		err = file.Close()
		if err != nil {
			return err
		}
		pageData.ModificationTime = fileInfo.ModTime()
		tmpl, err = siteGen.parseTemplate(ctx, path.Base(name), b.String(), nil)
		if err != nil {
			return err
		}
		return nil
	})

	g1.Go(func() error {
		g2, ctx2 := errgroup.WithContext(ctx1)
		markdownMu := sync.Mutex{}
		if remoteFS, ok := siteGen.fsys.(*RemoteFS); ok {
			cursor, err := sq.FetchCursor(ctx2, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {outputDir})" +
					" AND NOT is_dir" +
					" AND (" +
					"file_path LIKE '%.jpeg'" +
					" OR file_path LIKE '%.jpg'" +
					" OR file_path LIKE '%.png'" +
					" OR file_path LIKE '%.webp'" +
					" OR file_path LIKE '%.gif'" +
					" OR file_path LIKE '%.md'" +
					") " +
					" ORDER BY file_path",
				Values: []any{
					sq.StringParam("outputDir", outputDir),
				},
			}, func(row *sq.Row) *RemoteFile {
				file := &RemoteFile{
					ctx: ctx2,
				}
				file.info.filePath = row.String("file_path")
				file.buf = getBuffer(row, "CASE WHEN file_path LIKE '%.md' THEN text ELSE NULL END")
				return file
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			for cursor.Next() {
				file, err := cursor.Result()
				if err != nil {
					return err
				}
				name := path.Base(file.info.filePath)
				switch path.Ext(file.info.filePath) {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					pageData.Images = append(pageData.Images, Image{Parent: urlPath, Name: name})
				case ".md":
					g2.Go(func() error {
						defer file.Close()
						var b strings.Builder
						err = siteGen.markdown.Convert(file.buf.Bytes(), &b)
						if err != nil {
							return err
						}
						markdownMu.Lock()
						pageData.Markdown[name] = template.HTML(b.String())
						markdownMu.Unlock()
						return nil
					})
				}
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
		} else {
			dirEntries, err := siteGen.fsys.WithContext(ctx2).ReadDir(outputDir)
			if err != nil {
				return err
			}
			for _, dirEntry := range dirEntries {
				dirEntry := dirEntry
				name := dirEntry.Name()
				switch path.Ext(name) {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					pageData.Images = append(pageData.Images, Image{Parent: urlPath, Name: name})
				case ".md":
					g2.Go(func() error {
						file, err := siteGen.fsys.WithContext(ctx2).Open(path.Join(outputDir, name))
						if err != nil {
							return err
						}
						defer file.Close()
						buf := bufPool.Get().(*bytes.Buffer)
						buf.Reset()
						defer bufPool.Put(buf)
						_, err = buf.ReadFrom(file)
						if err != nil {
							return err
						}
						var b strings.Builder
						err = siteGen.markdown.Convert(buf.Bytes(), &b)
						if err != nil {
							return err
						}
						markdownMu.Lock()
						pageData.Markdown[name] = template.HTML(b.String())
						markdownMu.Unlock()
						return nil
					})
				}
			}
		}
		return g2.Wait()
	})

	g1.Go(func() error {
		pageDir := path.Join(siteGen.sitePrefix, "pages", urlPath)
		if remoteFS, ok := siteGen.fsys.(*RemoteFS); ok {
			childPages, err := sq.FetchAll(ctx1, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {pageDir})" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.html'" +
					" ORDER BY file_path",
			}, func(row *sq.Row) Page {
				page := Page{
					Parent: urlPath,
					Name:   path.Base(row.String("file_path")),
				}
				line := strings.TrimSpace(row.String("{}", sq.DialectExpression{
					Default: sq.Expr("substr(text, 1, instr(text, char(10))-1)"),
					Cases: []sq.DialectCase{{
						Dialect: "postgres",
						Result:  sq.Expr("split_part(text, chr(10), 1)"),
					}, {
						Dialect: "mysql",
						Result:  sq.Expr("substring_index(text, char(10), 1)"),
					}},
				}))
				if !strings.HasPrefix(line, "<!--") {
					return page
				}
				line = strings.TrimSpace(strings.TrimPrefix(line, "<!--"))
				if !strings.HasPrefix(line, "#title") {
					return page
				}
				line = strings.TrimSpace(strings.TrimPrefix(line, "#title"))
				n := strings.Index(line, "-->")
				if n < 0 {
					return page
				}
				page.Title = strings.TrimSpace(line[:n])
				return page
			})
			if err != nil {
				return err
			}
			pageData.ChildPages = childPages
		} else {
			dirEntries, err := siteGen.fsys.WithContext(ctx1).ReadDir(pageDir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			pageData.ChildPages = make([]Page, len(dirEntries))
			g2, ctx2 := errgroup.WithContext(ctx1)
			for i, dirEntry := range dirEntries {
				i, dirEntry := i, dirEntry
				g2.Go(func() error {
					if dirEntry.IsDir() || !strings.HasSuffix(dirEntry.Name(), ".html") {
						return nil
					}
					pageData.ChildPages[i].Parent = urlPath
					pageData.ChildPages[i].Name = dirEntry.Name()
					file, err := siteGen.fsys.WithContext(ctx2).Open(path.Join(pageDir, name))
					if err != nil {
						return err
					}
					defer file.Close()
					reader := readerPool.Get().(*bufio.Reader)
					reader.Reset(file)
					defer readerPool.Put(reader)
					done := false
					for !done {
						line, err := reader.ReadSlice('\n')
						if err != nil {
							if err != io.EOF {
								return err
							}
							done = true
						}
						line = bytes.TrimSpace(line)
						if !bytes.HasPrefix(line, []byte("<!--")) {
							break
						}
						line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("<!--")))
						if !bytes.HasPrefix(line, []byte("#title")) {
							break
						}
						line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("#title")))
						n := bytes.Index(line, []byte("-->"))
						if n < 0 {
							break
						}
						pageData.ChildPages[i].Title = string(bytes.TrimSpace(line[:n]))
					}
					return nil
				})
			}
			err = g2.Wait()
			if err != nil {
				return err
			}
			n := 0
			for _, childPage := range pageData.ChildPages {
				if childPage != (Page{}) {
					pageData.ChildPages[n] = childPage
					n++
				}
			}
			pageData.ChildPages = pageData.ChildPages[:n]
		}
		return nil
	})

	err := g1.Wait()
	if err != nil {
		return err
	}

	// Render the template contents into the output index.html.
	writer, err := siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		err := siteGen.fsys.WithContext(ctx).MkdirAll(outputDir, 0755)
		if err != nil {
			return err
		}
		writer, err = siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
		if err != nil {
			return err
		}
	}
	defer writer.Close()
	if siteGen.gzipGeneratedContent {
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(writer)
		defer gzipWriterPool.Put(gzipWriter)
		err = tmpl.Execute(gzipWriter, &pageData)
		if err != nil {
			return err
		}
		err = gzipWriter.Close()
		if err != nil {
			return err
		}
	} else {
		err = tmpl.Execute(writer, &pageData)
		if err != nil {
			return err
		}
	}
	err = writer.Close()
	if err != nil {
		return err
	}
	return nil
}

var funcMap = map[string]any{
	"join":             path.Join,
	"base":             path.Base,
	"ext":              path.Ext,
	"trimPrefix":       strings.TrimPrefix,
	"trimSuffix":       strings.TrimSuffix,
	"fileSizeToString": fileSizeToString,
	"safeHTML":         func(s string) template.HTML { return template.HTML(s) },
	"head": func(s string) string {
		head, _, _ := strings.Cut(s, "/")
		return head
	},
	"tail": func(s string) string {
		_, tail, _ := strings.Cut(s, "/")
		return tail
	},
	"list": func(v ...any) []any { return v },
	"dict": func(v ...any) (map[string]any, error) {
		dict := make(map[string]any)
		if len(dict)%2 != 0 {
			return nil, fmt.Errorf("odd number of arguments passed in")
		}
		for i := 0; i+1 < len(dict); i += 2 {
			key, ok := v[i].(string)
			if !ok {
				return nil, fmt.Errorf("value %d (%#v) is not a string", i, v[i])
			}
			value := v[i+1]
			dict[key] = value
		}
		return dict, nil
	},
	"dump": func(a ...any) template.HTML {
		// TODO: convert each argument into json and print each
		// argument out in a <pre style="white-space: pre-wrap"></pre>
		// tag.
		return ""
	},
}

type TemplateErrors map[string][]string

func (e TemplateErrors) Error() string {
	b, _ := json.MarshalIndent(e, "", "  ")
	return fmt.Sprintf("the following templates have errors: %s", string(b))
}

func (siteGen *SiteGenerator) parseTemplate(ctx context.Context, name, text string, callers []string) (*template.Template, error) {
	currentTemplate, err := template.New(name).Funcs(funcMap).Parse(text)
	if err != nil {
		return nil, TemplateErrors{
			name: {
				err.Error(),
			},
		}
	}
	var errmsgs []string
	internalTemplates := currentTemplate.Templates()
	for _, tmpl := range internalTemplates {
		internalName := tmpl.Name()
		if strings.HasSuffix(internalName, ".html") && internalName != name {
			errmsgs = append(errmsgs, fmt.Sprintf("%s: define %q: internal template name cannot end with .html", name, internalName))
		}
	}
	if len(errmsgs) > 0 {
		return nil, TemplateErrors{
			name: errmsgs,
		}
	}

	// Get the list of external templates referenced by the current template.
	var externalNames []string
	var node parse.Node
	var nodes []parse.Node
	for _, tmpl := range internalTemplates {
		if tmpl.Tree == nil || tmpl.Tree.Root == nil {
			continue
		}
		nodes = append(nodes, tmpl.Tree.Root.Nodes...)
		for len(nodes) > 0 {
			node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
			switch node := node.(type) {
			case *parse.ListNode:
				if node == nil {
					continue
				}
				nodes = append(nodes, node.Nodes...)
			case *parse.BranchNode:
				nodes = append(nodes, node.List, node.ElseList)
			case *parse.RangeNode:
				nodes = append(nodes, node.List, node.ElseList)
			case *parse.TemplateNode:
				if strings.HasSuffix(node.Name, ".html") {
					if !strings.HasPrefix(node.Name, "/themes/") {
						errmsgs = append(errmsgs, fmt.Sprintf("%s: template %q: external template name must start with /themes/", name, node.Name))
						continue
					}
					externalNames = append(externalNames, node.Name)
				}
			}
		}
	}
	if len(errmsgs) > 0 {
		return nil, TemplateErrors{
			name: errmsgs,
		}
	}
	// sort | uniq deduplication.
	slices.Sort(externalNames)
	externalNames = slices.Compact(externalNames)

	g, ctx := errgroup.WithContext(ctx)
	externalTemplates := make([]*template.Template, len(externalNames))
	externalTemplateErrs := make([]error, len(externalNames))
	for i, externalName := range externalNames {
		i, externalName := i, externalName
		g.Go(func() error {
			n := slices.Index(callers, externalName)
			if n > 0 {
				externalTemplateErrs[i] = fmt.Errorf("%s has a circular reference: %s", externalName, strings.Join(callers[n:], "=>")+" => "+externalName)
				return nil
			}

			// If a template is currently being parsed, wait for it to finish
			// before checking the templateCache for the result.
			siteGen.mu.Lock()
			wait := siteGen.templateInProgress[externalName]
			siteGen.mu.Unlock()
			if wait != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-wait:
					break
				}
			}
			siteGen.mu.Lock()
			cachedTemplate, ok := siteGen.templateCache[externalName]
			siteGen.mu.Unlock()
			if ok {
				// We found the template; add it to the slice and exit. Note
				// that the cachedTemplate may be nil, if parsing that template
				// had resulted in errors.
				externalTemplates[i] = cachedTemplate
				return nil
			}

			// We put a nil pointer into the templateCache first. This is to
			// indicate that we have already seen this template. If parsing
			// succeeds, we simply overwrite the cachedTemplate entry. If we
			// fail, the cachedTemplate pointer stays nil and should be treated
			// as a signal by other goroutines that parsing this template has
			// errors. Other goroutines are blocked from accessing the
			// cachedTemplate pointer until the wait channel is closed by the
			// defer function below (once this goroutine exits).
			wait = make(chan struct{})
			siteGen.mu.Lock()
			siteGen.templateCache[externalName] = nil
			siteGen.templateInProgress[externalName] = wait
			siteGen.mu.Unlock()
			defer func() {
				siteGen.mu.Lock()
				siteGen.templateCache[externalName] = cachedTemplate
				delete(siteGen.templateInProgress, externalName)
				close(wait)
				siteGen.mu.Unlock()
			}()

			file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "output", externalName))
			if err != nil {
				// If we cannot find the referenced template, it is not the
				// external template's fault but rather the current template's
				// fault for referencing a non-existent external template.
				// Therefore we return the error (associating it with the
				// current template) instead of adding it to the
				// externalTemplateErrs list.
				if errors.Is(err, fs.ErrNotExist) {
					return &fs.PathError{Op: "parsetemplate", Path: externalName, Err: fs.ErrNotExist}
				}
				externalTemplateErrs[i] = err
				return nil
			}
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				externalTemplateErrs[i] = err
				return nil
			}
			if fileInfo.IsDir() {
				// If the referenced template is not a file but a directory, it
				// is the current template's fault for referencing a directory
				// instead of a file. Therefore we return the error
				// (associating it with the current template) instead of adding
				// it to the externalTemplateErrs list.
				return &fs.PathError{Op: "parsetemplate", Path: externalName, Err: syscall.EISDIR}
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				externalTemplateErrs[i] = err
				return nil
			}
			err = file.Close()
			if err != nil {
				externalTemplateErrs[i] = err
				return nil
			}
			externalTemplate, err := siteGen.parseTemplate(ctx, externalName, b.String(), append(slices.Clone(callers), externalName))
			if err != nil {
				externalTemplateErrs[i] = err
				return nil
			}
			// NOTE: Before we execute any template it must be cloned. This is
			// because once a template has been executed it is no longer
			// pristine i.e. it cannot be added to another template using
			// AddParseTree (this is a html/template requirement, in order for
			// its contextually auto-escaped HTML feature to work).
			externalTemplates[i], err = externalTemplate.Clone()
			if err != nil {
				externalTemplateErrs[i] = err
				return nil
			}
			cachedTemplate = externalTemplate
			return nil
		})
	}
	err = g.Wait()
	if err != nil {
		return nil, TemplateErrors{
			name: {
				err.Error(),
			},
		}
	}

	mergedErrs := make(TemplateErrors)
	for i, err := range externalTemplateErrs {
		switch err := err.(type) {
		case nil:
			continue
		case TemplateErrors:
			for externalName, errmsgs := range err {
				mergedErrs[externalName] = append(mergedErrs[externalName], errmsgs...)
			}
		default:
			externalName := externalNames[i]
			mergedErrs[externalName] = append(mergedErrs[externalName], err.Error())
		}
	}
	var nilTemplateNames []string
	for i, tmpl := range externalTemplates {
		// A nil template means someone else attempted to parse that template
		// but failed (meaning it has errors), which blocks us from
		// successfully parsing the current template. Accumulate all the
		// failing template names and report it to the user.
		if tmpl == nil {
			nilTemplateNames = append(nilTemplateNames, externalNames[i])
		}
	}
	if len(nilTemplateNames) > 0 {
		mergedErrs[name] = append(mergedErrs[name], fmt.Sprintf("the following templates have errors: %s", strings.Join(nilTemplateNames, ", ")))
	}
	if len(mergedErrs) > 0 {
		return nil, mergedErrs
	}

	finalTemplate := template.New(name).Funcs(funcMap)
	for i, tmpl := range externalTemplates {
		for _, tmpl := range tmpl.Templates() {
			_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: add %s: %w", name, externalNames[i], tmpl.Name(), err)
			}
		}
	}
	for _, tmpl := range internalTemplates {
		_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
		if err != nil {
			return nil, fmt.Errorf("%s: add %s: %w", name, tmpl.Name(), err)
		}
	}
	return finalTemplate.Lookup(name), nil
}
