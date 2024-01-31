package nb9

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template/parse"
	"time"

	"github.com/bokwoon95/nb9/sq"
	"github.com/yuin/goldmark"
	"golang.org/x/net/html"
	"golang.org/x/sync/errgroup"
)

var ErrInvalidPostCategory = fmt.Errorf("invalid post category")

type SiteGenerator struct {
	Site               Site
	fsys               FS
	sitePrefix         string
	contentDomain      string
	cdnDomain          string
	mu                 sync.Mutex
	templateCache      map[string]*template.Template
	templateInProgress map[string]chan struct{}
}

type Site struct {
	Title      string
	Favicon    template.URL
	Emoji      string
	Lang       string
	Categories []string
	CodeStyle  string
}

func NewSiteGenerator(ctx context.Context, fsys FS, sitePrefix, contentDomain, cdnDomain string) (*SiteGenerator, error) {
	siteGen := &SiteGenerator{
		fsys:               fsys,
		sitePrefix:         sitePrefix,
		contentDomain:      contentDomain,
		cdnDomain:          cdnDomain,
		mu:                 sync.Mutex{},
		templateCache:      make(map[string]*template.Template),
		templateInProgress: make(map[string]chan struct{}),
	}
	b, err := fs.ReadFile(fsys, path.Join(sitePrefix, "site.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if len(b) > 0 {
		err := json.Unmarshal(b, &siteGen.Site)
		if err != nil {
			return nil, err
		}
	}
	if siteGen.Site.Emoji == "" {
		siteGen.Site.Emoji = "☕"
	}
	if siteGen.Site.Favicon == "" {
		siteGen.Site.Favicon = template.URL("data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + siteGen.Site.Emoji + "</text></svg>")
	}
	if siteGen.Site.Lang == "" {
		siteGen.Site.Lang = "en"
	}
	if siteGen.Site.CodeStyle == "" {
		siteGen.Site.CodeStyle = "onedark"
	}
	if siteGen.Site.Categories == nil {
		if remoteFS, ok := fsys.(*RemoteFS); ok {
			categories, err := sq.FetchAll(ctx, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
					" AND is_dir" +
					" ORDER BY file_path",
				Values: []any{
					sq.StringParam("filePath", path.Join(sitePrefix, "posts")),
				},
			}, func(row *sq.Row) string {
				return path.Base(row.String("file_path"))
			})
			if err != nil {
				return nil, err
			}
			siteGen.Site.Categories = categories
		} else {
			dirEntries, err := fsys.ReadDir(path.Join(sitePrefix, "posts"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
			for _, dirEntry := range dirEntries {
				if !dirEntry.IsDir() {
					continue
				}
				siteGen.Site.Categories = append(siteGen.Site.Categories, dirEntry.Name())
			}
		}
	}
	return siteGen, nil
}

func (siteGen *SiteGenerator) ParseTemplate(ctx context.Context, name, text string, callers []string) (*template.Template, error) {
	currentTemplate, err := template.New(name).Funcs(funcMap).Parse(text)
	if err != nil {
		return nil, TemplateParseError{name: {err.Error()}}
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
		return nil, TemplateParseError{name: errmsgs}
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
		return nil, TemplateParseError{name: errmsgs}
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
			// succeeds, we simply overwrite the nil entry with the parsed
			// template. If we fail, the cachedTemplate pointer stays nil and
			// should be treated as a signal by other goroutines that parsing
			// this template has errors. Other goroutines are blocked from
			// accessing the cachedTemplate pointer until the wait channel is
			// closed by the defer function below (once this goroutine exits).
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
			newCallers := append(append(make([]string, 0, len(callers)+1), callers...), externalName)
			externalTemplate, err := siteGen.ParseTemplate(ctx, externalName, b.String(), newCallers)
			if err != nil {
				externalTemplateErrs[i] = err
				return nil
			}
			// Important! Before we execute any template, it must be cloned.
			// This is because once a template has been executed it is no
			// longer pristine i.e. it cannot be added to another template
			// using AddParseTree (html/template has this restriction in order
			// for its contextually auto-escaped HTML feature to work).
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
		return nil, TemplateParseError{name: {err.Error()}}
	}

	parseErrors := make(TemplateParseError)
	for i, err := range externalTemplateErrs {
		switch err := err.(type) {
		case nil:
			continue
		case TemplateParseError:
			for externalName, errmsgs := range err {
				parseErrors[externalName] = append(parseErrors[externalName], errmsgs...)
			}
		default:
			externalName := externalNames[i]
			parseErrors[externalName] = append(parseErrors[externalName], err.Error())
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
		parseErrors[name] = append(parseErrors[name], fmt.Sprintf("the following templates have errors: %s", strings.Join(nilTemplateNames, ", ")))
	}
	if len(parseErrors) > 0 {
		return nil, parseErrors
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

type PageData struct {
	Site             Site
	Parent           string
	Name             string
	ChildPages       []Page
	Markdown         map[string]template.HTML
	Images           []Image
	ModificationTime time.Time
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

func (siteGen *SiteGenerator) GeneratePage(ctx context.Context, filePath, text string, markdown goldmark.Markdown) error {
	urlPath := strings.TrimPrefix(filePath, "pages/")
	if urlPath == "index.html" {
		urlPath = ""
	} else {
		urlPath = strings.TrimSuffix(urlPath, path.Ext(urlPath))
	}
	outputDir := path.Join(siteGen.sitePrefix, "output", urlPath)
	pageData := PageData{
		Site:             siteGen.Site,
		Parent:           path.Dir(urlPath),
		Name:             path.Base(urlPath),
		ModificationTime: time.Now().UTC(),
	}
	if pageData.Parent == "." {
		pageData.Parent = ""
	}
	var err error
	var tmpl *template.Template
	g1, ctx1 := errgroup.WithContext(ctx)
	g1.Go(func() error {
		const doctype = "<!DOCTYPE html>"
		text := strings.TrimSpace(text)
		if len(text) < len(doctype) || !strings.EqualFold(text[:len(doctype)], doctype) {
			text = "<!DOCTYPE html>" +
				"\n<html lang='{{ $.Site.Lang }}'>" +
				"\n<meta charset='utf-8'>" +
				"\n<meta name='viewport' content='width=device-width, initial-scale=1'>" +
				"\n<link rel='icon' href='{{ $.Site.Favicon }}'>" +
				"\n" + text
		}
		tmpl, err = siteGen.ParseTemplate(ctx1, strings.TrimPrefix(filePath, "pages/"), text, nil)
		if err != nil {
			return err
		}
		return nil
	})
	g1.Go(func() error {
		markdownMu := sync.Mutex{}
		if remoteFS, ok := siteGen.fsys.(*RemoteFS); ok {
			cursor, err := sq.FetchCursor(ctx1, remoteFS.filesDB, sq.Query{
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
					ctx:  ctx1,
					info: &RemoteFileInfo{},
				}
				file.info.filePath = row.String("file_path")
				b := bufPool.Get().(*bytes.Buffer).Bytes()
				row.Scan(&b, "CASE WHEN file_path LIKE '%.md' THEN text ELSE NULL END")
				if b != nil {
					file.buf = bytes.NewBuffer(b)
				}
				return file
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
				name := path.Base(file.info.filePath)
				switch path.Ext(file.info.filePath) {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					pageData.Images = append(pageData.Images, Image{Parent: urlPath, Name: name})
				case ".md":
					g2.Go(func() error {
						err := ctx2.Err()
						if err != nil {
							return err
						}
						defer file.Close()
						var b strings.Builder
						err = markdown.Convert(file.buf.Bytes(), &b)
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
			err = g2.Wait()
			if err != nil {
				return err
			}
		} else {
			dirEntries, err := siteGen.fsys.WithContext(ctx1).ReadDir(outputDir)
			if err != nil {
				return err
			}
			g2, ctx2 := errgroup.WithContext(ctx1)
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
						defer func() {
							if buf.Cap() <= maxPoolableBufferCapacity {
								buf.Reset()
								bufPool.Put(buf)
							}
						}()
						_, err = buf.ReadFrom(file)
						if err != nil {
							return err
						}
						var b strings.Builder
						err = markdown.Convert(buf.Bytes(), &b)
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
			err = g2.Wait()
			if err != nil {
				return err
			}
		}
		return nil
	})
	g1.Go(func() error {
		pageDir := path.Join(siteGen.sitePrefix, "pages", urlPath)
		if remoteFS, ok := siteGen.fsys.(*RemoteFS); ok {
			pageData.ChildPages, err = sq.FetchAll(ctx1, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {pageDir})" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.html'" +
					" ORDER BY file_path",
				Values: []any{
					sq.StringParam("pageDir", pageDir),
				},
			}, func(row *sq.Row) Page {
				page := Page{
					Parent: urlPath,
					Name:   path.Base(row.String("file_path")),
				}
				// TODO: oh my god we do title detection here but what if the
				// user wants to use 1. set a custom lang or 2. use a custom
				// favicon? Then <!DOCTYPE> has to come first :/ and we can't
				// use <!-- #title --> anymore
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
				if !strings.HasSuffix(line, "-->") {
					return page
				}
				page.Title = strings.TrimSpace(strings.TrimSuffix(line, "-->"))
				return page
			})
			if err != nil {
				return err
			}
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
					name := dirEntry.Name()
					if dirEntry.IsDir() || !strings.HasSuffix(name, ".html") {
						return nil
					}
					pageData.ChildPages[i].Parent = urlPath
					pageData.ChildPages[i].Name = name
					file, err := siteGen.fsys.WithContext(ctx2).Open(path.Join(pageDir, name))
					if err != nil {
						return err
					}
					defer file.Close()
					reader := readerPool.Get().(*bufio.Reader)
					defer func() {
						reader.Reset(file)
						readerPool.Put(reader)
					}()
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
						if !bytes.HasSuffix(line, []byte("-->")) {
							break
						}
						pageData.ChildPages[i].Title = string(bytes.TrimSpace(bytes.TrimSuffix(line, []byte("-->"))))
						break
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
	err = g1.Wait()
	if err != nil {
		return err
	}
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
	if siteGen.cdnDomain == "" {
		err = tmpl.Execute(writer, &pageData)
		if err != nil {
			return &TemplateExecutionError{Err: err}
		}
	} else {
		pipeReader, pipeWriter := io.Pipe()
		result := make(chan error, 1)
		go func() {
			result <- rewriteURLs(writer, pipeReader, siteGen.cdnDomain, siteGen.sitePrefix, urlPath)
		}()
		err = tmpl.Execute(pipeWriter, &pageData)
		if err != nil {
			return &TemplateExecutionError{Err: err}
		}
		pipeWriter.Close()
		err = <-result
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

type PostData struct {
	Site             Site
	Category         string
	Name             string
	Title            string
	Content          template.HTML
	Images           []Image
	CreationTime     time.Time
	ModificationTime time.Time
}

func (siteGen *SiteGenerator) GeneratePost(ctx context.Context, filePath, text string, markdown goldmark.Markdown, tmpl *template.Template) error {
	urlPath := strings.TrimSuffix(filePath, path.Ext(filePath))
	outputDir := path.Join(siteGen.sitePrefix, "output", urlPath)
	postData := PostData{
		Site:             siteGen.Site,
		Category:         path.Dir(strings.TrimPrefix(urlPath, "posts/")),
		Name:             path.Base(strings.TrimPrefix(urlPath, "posts/")),
		ModificationTime: time.Now().UTC(),
	}
	if strings.Contains(postData.Category, "/") {
		return ErrInvalidPostCategory
	}
	if postData.Category == "." {
		postData.Category = ""
	}
	prefix, _, _ := strings.Cut(path.Base(urlPath), "-")
	if len(prefix) == 0 || len(prefix) > 8 {
		return nil
	}
	b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
	if len(b) != 5 {
		return nil
	}
	var timestamp [8]byte
	copy(timestamp[len(timestamp)-5:], b)
	postData.CreationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)
	var err error
	g1, ctx1 := errgroup.WithContext(ctx)
	g1.Go(func() error {
		err := ctx1.Err()
		if err != nil {
			return err
		}
		contentBytes := []byte(text)
		// Title
		var line []byte
		remainder := contentBytes
		for len(remainder) > 0 {
			line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			postData.Title = stripMarkdownStyles(line)
			break
		}
		// Content
		var b strings.Builder
		err = markdown.Convert(contentBytes, &b)
		if err != nil {
			return err
		}
		postData.Content = template.HTML(b.String())
		return nil
	})
	g1.Go(func() error {
		if remoteFS, ok := siteGen.fsys.(*RemoteFS); ok {
			cursor, err := sq.FetchCursor(ctx1, remoteFS.filesDB, sq.Query{
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
					") " +
					" ORDER BY file_path",
				Values: []any{
					sq.StringParam("outputDir", outputDir),
				},
			}, func(row *sq.Row) string {
				return path.Base(row.String("file_path"))
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			for cursor.Next() {
				name, err := cursor.Result()
				if err != nil {
					return err
				}
				postData.Images = append(postData.Images, Image{Parent: urlPath, Name: name})
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
		} else {
			dirEntries, err := siteGen.fsys.WithContext(ctx1).ReadDir(outputDir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			for _, dirEntry := range dirEntries {
				name := dirEntry.Name()
				if dirEntry.IsDir() {
					continue
				}
				switch path.Ext(name) {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					postData.Images = append(postData.Images, Image{Parent: urlPath, Name: name})
				}
			}
		}
		return nil
	})
	err = g1.Wait()
	if err != nil {
		return err
	}
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
	if siteGen.cdnDomain == "" {
		err = tmpl.Execute(writer, &postData)
		if err != nil {
			return &TemplateExecutionError{Err: err}
		}
	} else {
		pipeReader, pipeWriter := io.Pipe()
		result := make(chan error, 1)
		go func() {
			result <- rewriteURLs(writer, pipeReader, siteGen.cdnDomain, siteGen.sitePrefix, urlPath)
		}()
		err = tmpl.Execute(pipeWriter, &postData)
		if err != nil {
			return &TemplateExecutionError{Err: err}
		}
		pipeWriter.Close()
		err = <-result
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

type Post struct {
	Category         string
	Name             string
	Title            string
	Preview          string
	Content          template.HTML
	CreationTime     time.Time
	ModificationTime time.Time
	text             []byte
}

type PostListData struct {
	Site       Site
	Category   string
	Pagination Pagination
	Posts      []Post
}

func (siteGen *SiteGenerator) GeneratePostList(ctx context.Context, category string, markdown goldmark.Markdown, tmpl *template.Template) (int, error) {
	var config struct {
		PostsPerPage int `json:"postsPerPage"`
	}
	if strings.Contains(category, "/") {
		return 0, ErrInvalidPostCategory
	}
	b, err := fs.ReadFile(siteGen.fsys.WithContext(ctx), path.Join(siteGen.sitePrefix, "postlist.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	if len(b) > 0 {
		err := json.Unmarshal(b, &config)
		if err != nil {
			return 0, err
		}
	}
	if config.PostsPerPage <= 0 {
		config.PostsPerPage = 100
	}
	if remoteFS, ok := siteGen.fsys.(*RemoteFS); ok {
		count, err := sq.FetchOne(ctx, remoteFS.filesDB, sq.Query{
			Dialect: remoteFS.filesDialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
				" AND NOT is_dir" +
				" AND file_path LIKE '%.md'",
			Values: []any{
				sq.StringParam("parent", path.Join(siteGen.sitePrefix, "posts", category)),
			},
		}, func(row *sq.Row) int {
			return row.Int("COUNT(*)")
		})
		if err != nil {
			return 0, err
		}
		lastPage := int(math.Ceil(float64(count) / float64(config.PostsPerPage)))
		g1, ctx1 := errgroup.WithContext(ctx)
		g1.Go(func() error {
			filePaths, err := sq.FetchAll(ctx1, remoteFS.filesDB, sq.Query{
				Dialect: remoteFS.filesDialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
					" AND is_dir",
				Values: []any{
					sq.StringParam("parent", path.Join(siteGen.sitePrefix, "output/posts", category)),
				},
			}, func(row *sq.Row) string {
				return row.String("file_path")
			})
			if err != nil {
				return err
			}
			g2, ctx2 := errgroup.WithContext(ctx1)
			for _, filePath := range filePaths {
				filePath := filePath
				n, err := strconv.Atoi(path.Base(filePath))
				if err != nil {
					continue
				}
				if n <= lastPage {
					continue
				}
				g2.Go(func() error {
					_, err := sq.Exec(ctx2, remoteFS.filesDB, sq.Query{
						Dialect: remoteFS.filesDialect,
						Format:  "DELETE FROM files WHERE file_path = {filePath} OR file_path LIKE {pattern} ESCAPE '\\'",
						Values: []any{
							sq.StringParam("filePath", filePath),
							sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(filePath)+"/%"),
						},
					})
					if err != nil {
						return err
					}
					return nil
				})
			}
			err = g2.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		cursor, err := sq.FetchCursor(ctx1, remoteFS.filesDB, sq.Query{
			Dialect: remoteFS.filesDialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
				" AND NOT is_dir" +
				" AND file_path LIKE '%.md'" +
				" ORDER BY file_path DESC",
			Values: []any{
				sq.StringParam("parent", path.Join(siteGen.sitePrefix, "posts", category)),
			},
		}, func(row *sq.Row) Post {
			var post Post
			post.Category = category
			name := path.Base(row.String("file_path"))
			post.Name = strings.TrimSuffix(name, path.Ext(name))
			post.ModificationTime = row.Time("mod_time")
			post.text = bufPool.Get().(*bytes.Buffer).Bytes()
			row.Scan(&post.text, "text")
			return post
		})
		if err != nil {
			return 0, err
		}
		defer cursor.Close()
		page := 1
		batch := make([]Post, 0, config.PostsPerPage)
		for cursor.Next() {
			post, err := cursor.Result()
			if err != nil {
				return page, err
			}
			batch = append(batch, post)
			if len(batch) >= config.PostsPerPage {
				currentPage := page
				page++
				posts := slices.Clone(batch)
				batch = batch[:0]
				g1.Go(func() error {
					return siteGen.GeneratePostListPage(ctx1, category, markdown, tmpl, lastPage, currentPage, posts)
				})
			}
		}
		err = cursor.Close()
		if err != nil {
			return page, err
		}
		if len(batch) > 0 {
			g1.Go(func() error {
				return siteGen.GeneratePostListPage(ctx1, category, markdown, tmpl, lastPage, page, batch)
			})
		}
		err = g1.Wait()
		if err != nil {
			return page, err
		}
		if page == 1 && len(batch) == 0 {
			err := siteGen.GeneratePostListPage(ctx, category, markdown, tmpl, 1, 1, nil)
			if err != nil {
				return page, err
			}
		}
		return page, nil
	}
	dirEntries, err := siteGen.fsys.WithContext(ctx).ReadDir(path.Join(siteGen.sitePrefix, "posts", category))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue
		}
		if !strings.HasSuffix(dirEntry.Name(), ".md") {
			continue
		}
		dirEntries[n] = dirEntry
		n++
	}
	dirEntries = dirEntries[:n]
	slices.Reverse(dirEntries)
	lastPage := int(math.Ceil(float64(len(dirEntries)) / float64(config.PostsPerPage)))
	g1, ctx1 := errgroup.WithContext(ctx)
	g1.Go(func() error {
		dirEntries, err := siteGen.fsys.WithContext(ctx1).ReadDir(path.Join(siteGen.sitePrefix, "output/posts", category))
		if err != nil {
			return err
		}
		g2, ctx2 := errgroup.WithContext(ctx1)
		for _, dirEntry := range dirEntries {
			dirEntry := dirEntry
			if !dirEntry.IsDir() {
				continue
			}
			n, err := strconv.Atoi(dirEntry.Name())
			if err != nil {
				continue
			}
			if n <= lastPage {
				continue
			}
			g2.Go(func() error {
				return siteGen.fsys.WithContext(ctx2).RemoveAll(path.Join(siteGen.sitePrefix, "output/posts", category, strconv.Itoa(n)))
			})
		}
		err = g2.Wait()
		if err != nil {
			return err
		}
		return nil
	})
	page := 1
	batch := make([]Post, 0, config.PostsPerPage)
	for _, dirEntry := range dirEntries {
		fileInfo, err := dirEntry.Info()
		if err != nil {
			return page, err
		}
		name := fileInfo.Name()
		batch = append(batch, Post{
			Category:         category,
			Name:             strings.TrimSuffix(name, path.Ext(name)),
			ModificationTime: fileInfo.ModTime(),
		})
		if len(batch) >= config.PostsPerPage {
			currentPage := page
			page++
			posts := slices.Clone(batch)
			batch = batch[:0]
			g1.Go(func() error {
				return siteGen.GeneratePostListPage(ctx1, category, markdown, tmpl, lastPage, currentPage, posts)
			})
		}
	}
	if len(batch) > 0 {
		g1.Go(func() error {
			return siteGen.GeneratePostListPage(ctx1, category, markdown, tmpl, lastPage, page, batch)
		})
	}
	err = g1.Wait()
	if err != nil {
		return page, err
	}
	if page == 1 && len(batch) == 0 {
		err := siteGen.GeneratePostListPage(ctx, category, markdown, tmpl, 1, 1, nil)
		if err != nil {
			return page, err
		}
	}
	return page, nil
}

func (siteGen *SiteGenerator) GeneratePostListPage(ctx context.Context, category string, markdown goldmark.Markdown, tmpl *template.Template, lastPage, currentPage int, posts []Post) error {
	n := 0
	for _, post := range posts {
		prefix, _, _ := strings.Cut(post.Name, "-")
		if prefix == "" || len(prefix) > 8 {
			if post.text != nil && len(post.text) <= maxPoolableBufferCapacity {
				post.text = post.text[:0]
				bufPool.Put(bytes.NewBuffer(post.text))
				post.text = nil
			}
			continue
		}
		b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
		if len(b) != 5 {
			if post.text != nil && len(post.text) <= maxPoolableBufferCapacity {
				post.text = post.text[:0]
				bufPool.Put(bytes.NewBuffer(post.text))
				post.text = nil
			}
			continue
		}
		var timestamp [8]byte
		copy(timestamp[len(timestamp)-5:], b)
		post.CreationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)
		posts[n] = post
		n++
	}
	posts = posts[:n]
	g1A, ctx1A := errgroup.WithContext(ctx)
	for i := range posts {
		i := i
		g1A.Go(func() error {
			if posts[i].text != nil {
				defer func() {
					if len(posts[i].text) <= maxPoolableBufferCapacity {
						posts[i].text = posts[i].text[:0]
						bufPool.Put(bytes.NewBuffer(posts[i].text))
						posts[i].text = nil
					}
				}()
			} else {
				file, err := siteGen.fsys.WithContext(ctx1A).Open(path.Join(siteGen.sitePrefix, "posts", category, posts[i].Name))
				if err != nil {
					return err
				}
				defer file.Close()
				buf := bufPool.Get().(*bytes.Buffer)
				defer func() {
					if buf.Cap() <= maxPoolableBufferCapacity {
						buf.Reset()
						bufPool.Put(buf)
						posts[i].text = nil
					}
				}()
				_, err = buf.ReadFrom(file)
				if err != nil {
					return err
				}
				posts[i].text = buf.Bytes()
			}
			var line []byte
			remainder := posts[i].text
			for len(remainder) > 0 {
				line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				if posts[i].Title == "" {
					posts[i].Title = stripMarkdownStyles(line)
					continue
				}
				if posts[i].Preview == "" {
					posts[i].Preview = stripMarkdownStyles(line)
					continue
				}
				break
			}
			var b strings.Builder
			err := markdown.Convert(posts[i].text, &b)
			if err != nil {
				return err
			}
			posts[i].Content = template.HTML(b.String())
			return nil
		})
	}
	err := g1A.Wait()
	if err != nil {
		return err
	}
	postListData := PostListData{
		Site:       siteGen.Site,
		Category:   category,
		Pagination: NewPagination(currentPage, lastPage, 9),
		Posts:      posts,
	}
	outputDir := path.Join(siteGen.sitePrefix, "output/posts", postListData.Category)
	if currentPage != 1 {
		writer, err := siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, strconv.Itoa(currentPage), "index.html"), 0644)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			err := siteGen.fsys.WithContext(ctx).MkdirAll(path.Join(outputDir, strconv.Itoa(currentPage)), 0755)
			if err != nil {
				return err
			}
			writer, err = siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, strconv.Itoa(currentPage), "index.html"), 0644)
			if err != nil {
				return err
			}
		}
		defer writer.Close()
		if siteGen.cdnDomain == "" {
			err = tmpl.Execute(writer, &postListData)
			if err != nil {
				return &TemplateExecutionError{Err: err}
			}
		} else {
			pipeReader, pipeWriter := io.Pipe()
			result := make(chan error, 1)
			go func() {
				result <- rewriteURLs(writer, pipeReader, siteGen.cdnDomain, siteGen.sitePrefix, "")
			}()
			err = tmpl.Execute(pipeWriter, &postListData)
			if err != nil {
				return &TemplateExecutionError{Err: err}
			}
			pipeWriter.Close()
			err = <-result
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
	g1B, ctx1B := errgroup.WithContext(ctx)
	g1B.Go(func() error {
		writer, err := siteGen.fsys.WithContext(ctx1B).OpenWriter(path.Join(outputDir, "index.html"), 0644)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			err := siteGen.fsys.WithContext(ctx1B).MkdirAll(outputDir, 0755)
			if err != nil {
				return err
			}
			writer, err = siteGen.fsys.WithContext(ctx1B).OpenWriter(path.Join(outputDir, "index.html"), 0644)
			if err != nil {
				return err
			}
		}
		defer writer.Close()
		if siteGen.cdnDomain == "" {
			err = tmpl.Execute(writer, &postListData)
			if err != nil {
				return &TemplateExecutionError{Err: err}
			}
		} else {
			pipeReader, pipeWriter := io.Pipe()
			result := make(chan error, 1)
			go func() {
				result <- rewriteURLs(writer, pipeReader, siteGen.cdnDomain, siteGen.sitePrefix, "")
			}()
			err = tmpl.Execute(pipeWriter, &postListData)
			if err != nil {
				return &TemplateExecutionError{Err: err}
			}
			pipeWriter.Close()
			err = <-result
			if err != nil {
				return err
			}
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		if lastPage > 1 {
			file, err := siteGen.fsys.WithContext(ctx1B).Open(path.Join(outputDir, "index.html"))
			if err != nil {
				return err
			}
			defer file.Close()
			writer, err := siteGen.fsys.WithContext(ctx1B).OpenWriter(path.Join(outputDir, "1", "index.html"), 0644)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
				err := siteGen.fsys.WithContext(ctx1B).MkdirAll(path.Join(outputDir, "1"), 0755)
				if err != nil {
					return err
				}
				writer, err = siteGen.fsys.WithContext(ctx1B).OpenWriter(path.Join(outputDir, "1", "index.html"), 0644)
				if err != nil {
					return err
				}
			}
			defer writer.Close()
			_, err = io.Copy(writer, file)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
		}
		return nil
	})
	g1B.Go(func() error {
		scheme := "https://"
		contentDomain := siteGen.sitePrefix
		if !strings.Contains(siteGen.sitePrefix, ".") {
			if siteGen.contentDomain == "localhost" || strings.HasPrefix(siteGen.contentDomain, "localhost:") {
				scheme = "http://"
			}
			if siteGen.sitePrefix != "" {
				contentDomain = strings.TrimPrefix(siteGen.sitePrefix, "@") + "." + siteGen.contentDomain
			} else {
				contentDomain = siteGen.contentDomain
			}
		}
		feed := AtomFeed{
			Xmlns:   "http://www.w3.org/2005/Atom",
			ID:      scheme + contentDomain,
			Title:   siteGen.Site.Title,
			Updated: time.Now().UTC().Format("2006-01-02 15:04:05Z"),
			Link: []AtomLink{{
				Href: scheme + contentDomain + "/" + path.Join("posts", postListData.Category) + "/index.atom",
				Rel:  "self",
			}, {
				Href: scheme + contentDomain + "/" + path.Join("posts", postListData.Category) + "/",
				Rel:  "alternate",
			}},
			Entry: make([]AtomEntry, len(postListData.Posts)),
		}
		for i, post := range postListData.Posts {
			// ID: tag:bokwoon.nbrew.io,yyyy-mm-dd:1jjdz28
			var timestamp [8]byte
			binary.BigEndian.PutUint64(timestamp[:], uint64(post.CreationTime.Unix()))
			prefix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			feed.Entry[i] = AtomEntry{
				ID:        "tag:" + contentDomain + "," + post.CreationTime.UTC().Format("2006-01-02") + ":" + prefix,
				Title:     post.Title,
				Published: post.CreationTime.UTC().Format("2006-01-02 15:04:05Z"),
				Updated:   post.ModificationTime.UTC().Format("2006-01-02 15:04:05Z"),
				Link: []AtomLink{{
					Href: scheme + contentDomain + "/" + path.Join("posts", post.Category, post.Name) + "/",
					Rel:  "alternate",
				}},
				Summary: AtomText{
					Type:    "text",
					Content: string(post.Preview),
				},
				Content: AtomText{
					Type:    "html",
					Content: string(post.Content),
				},
			}
		}
		writer, err := siteGen.fsys.WithContext(ctx1B).OpenWriter(path.Join(outputDir, "index.atom"), 0644)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			err := siteGen.fsys.WithContext(ctx1B).MkdirAll(outputDir, 0755)
			if err != nil {
				return err
			}
			writer, err = siteGen.fsys.WithContext(ctx1B).OpenWriter(path.Join(outputDir, "index.atom"), 0644)
			if err != nil {
				return err
			}
		}
		defer writer.Close()
		_, err = writer.Write([]byte(xml.Header))
		if err != nil {
			return err
		}
		encoder := xml.NewEncoder(writer)
		encoder.Indent("", "  ")
		err = encoder.Encode(&feed)
		if err != nil {
			return err
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		return nil
	})
	err = g1B.Wait()
	if err != nil {
		return err
	}
	return nil
}

func rewriteURLs(writer io.Writer, reader io.Reader, cdnDomain, sitePrefix, urlPath string) error {
	tokenizer := html.NewTokenizer(reader)
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				return nil
			}
			return err
		case html.TextToken:
			_, err := writer.Write(tokenizer.Text())
			if err != nil {
				return err
			}
		case html.DoctypeToken:
			for _, b := range [...][]byte{
				[]byte("<!DOCTYPE "), tokenizer.Text(), []byte(">"),
			} {
				_, err := writer.Write(b)
				if err != nil {
					return err
				}
			}
		case html.CommentToken:
			for _, b := range [...][]byte{
				[]byte("<!--"), tokenizer.Text(), []byte("-->"),
			} {
				_, err := writer.Write(b)
				if err != nil {
					return err
				}
			}
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			switch tokenType {
			case html.StartTagToken, html.SelfClosingTagToken:
				_, err := writer.Write([]byte("<"))
				if err != nil {
					return err
				}
			case html.EndTagToken:
				_, err := writer.Write([]byte("</"))
				if err != nil {
					return err
				}
			}
			var key, val []byte
			name, moreAttr := tokenizer.TagName()
			_, err := writer.Write(name)
			if err != nil {
				return err
			}
			isImgTag := bytes.Equal(name, []byte("img"))
			for moreAttr {
				key, val, moreAttr = tokenizer.TagAttr()
				if isImgTag && bytes.Equal(key, []byte("src")) {
					uri, err := url.Parse(string(val))
					if err == nil && uri.Scheme == "" && uri.Host == "" {
						switch path.Ext(uri.Path) {
						case ".jpeg", ".jpg", ".png", ".webp", ".gif":
							uri.Scheme = "https"
							uri.Host = cdnDomain
							if strings.HasPrefix(uri.Path, "/") {
								if sitePrefix != "" {
									uri.Path = "/" + path.Join(sitePrefix, uri.Path)
								}
								val = []byte(uri.String())
							} else {
								if urlPath != "" {
									uri.Path = "/" + path.Join(sitePrefix, urlPath, uri.Path)
									val = []byte(uri.String())
								}
							}
						}
					}
				}
				for _, b := range [...][]byte{
					[]byte(` `), key, []byte(`="`), val, []byte(`"`),
				} {
					_, err := writer.Write(b)
					if err != nil {
						return err
					}
				}
			}
			switch tokenType {
			case html.StartTagToken, html.EndTagToken:
				_, err = writer.Write([]byte(">"))
				if err != nil {
					return err
				}
			case html.SelfClosingTagToken:
				_, err = writer.Write([]byte("/>"))
				if err != nil {
					return err
				}
			}
		}
	}
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

type TemplateParseError map[string][]string

func (parseErrors TemplateParseError) Error() string {
	b, _ := json.MarshalIndent(parseErrors, "", "  ")
	return fmt.Sprintf("the following templates have errors: %s", string(b))
}

func (parseErr TemplateParseError) List() []string {
	var n int
	names := make([]string, 0, len(parseErr))
	for name, errmsgs := range parseErr {
		names = append(names, name)
		n += len(errmsgs)
	}
	slices.Sort(names)
	errmsgs := make([]string, 0, n)
	for _, name := range names {
		for _, errmsg := range parseErr[name] {
			errmsgs = append(errmsgs, name+": "+errmsg)
		}
	}
	return errmsgs
}

type TemplateExecutionError struct{ Err error }

func (executionErr *TemplateExecutionError) Error() string {
	return executionErr.Err.Error()
}

func (executionErr *TemplateExecutionError) Unwrap() error {
	return executionErr.Err
}

type Pagination struct {
	First    string
	Previous string
	Current  string
	Next     string
	Last     string
	Numbers  []string
}

func NewPagination(currentPage, lastPage, visiblePages int) Pagination {
	const numConsecutiveNeighbours = 2
	if visiblePages%2 == 0 {
		panic("even number of visiblePages")
	}
	minVisiblePages := (numConsecutiveNeighbours * 2) + 1
	if visiblePages < minVisiblePages {
		panic("visiblePages cannot be lower than " + strconv.Itoa(minVisiblePages))
	}
	pagination := Pagination{
		First:   "1",
		Current: strconv.Itoa(currentPage),
		Last:    strconv.Itoa(lastPage),
	}
	previous := currentPage - 1
	if previous >= 1 {
		pagination.Previous = strconv.Itoa(previous)
	}
	next := currentPage + 1
	if next <= lastPage {
		pagination.Next = strconv.Itoa(next)
	}
	// If there are fewer pages than visible pages, iterate through all the
	// page numbers.
	if lastPage <= visiblePages {
		pagination.Numbers = make([]string, 0, lastPage)
		for page := 1; page <= lastPage; page++ {
			pagination.Numbers = append(pagination.Numbers, strconv.Itoa(page))
		}
		return pagination
	}
	// Slots corresponds to the available slots in pagination.Numbers, storing
	// the page numbers as integers. They will be converted to strings later.
	slots := make([]int, visiblePages)
	// A unit is a tenth of the maximum number of pages. The rationale is that
	// users should have to paginate at most 10 such units to get from start to
	// end, no matter how many pages there are.
	unit := lastPage / 10
	if currentPage-1 < len(slots)>>1 {
		// If there are fewer pages on the left than half of the slots, the
		// current page will skew more towards the left. We fill in consecutive
		// page numbers from left to right, then fill in the remaining slots.
		numConsecutive := (currentPage - 1) + 1 + numConsecutiveNeighbours
		consecutiveStart := 0
		consecutiveEnd := numConsecutive - 1
		page := 1
		for i := consecutiveStart; i <= consecutiveEnd; i++ {
			slots[i] = page
			page += 1
		}
		// The last slot is always the last page.
		slots[len(slots)-1] = lastPage
		// Fill in the remaining slots with either an exponentially changing or
		// linearly changing number depending on which is more appropriate.
		remainingSlots := slots[consecutiveEnd+1 : len(slots)-1]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
			exponentialNum := currentPage + unit>>shift
			linearNum := currentPage + delta
			if exponentialNum > linearNum && exponentialNum < lastPage {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	} else if lastPage-currentPage < len(slots)>>1 {
		// If there are fewer pages on the right than half of the slots, the
		// current page will skew more towards the right. We fill in
		// consecutive page numbers from the right to left, then fill in the
		// remaining slots.
		numConsecutive := (lastPage - currentPage) + 1 + numConsecutiveNeighbours
		consecutiveStart := len(slots) - 1
		consecutiveEnd := len(slots) - numConsecutive
		page := lastPage
		for i := consecutiveStart; i >= consecutiveEnd; i-- {
			slots[i] = page
			page -= 1
		}
		// The first slot is always the first page.
		slots[0] = 1
		// Fill in the remaining slots with either an exponentially changing or
		// linearly changing number depending on which is more appropriate.
		remainingSlots := slots[1:consecutiveEnd]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := 1; i < consecutiveEnd; i++ {
			exponentialNum := currentPage - unit>>shift
			linearNum := currentPage - delta
			if exponentialNum < linearNum && exponentialNum > 1 {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	} else {
		// If we reach here, it means the current page is directly in the
		// center the slots. Fill in the consecutive band of numbers around the
		// center, then fill in the remaining slots to the left and to the
		// right.
		consecutiveStart := len(slots)>>1 - numConsecutiveNeighbours
		consecutiveEnd := len(slots)>>1 + numConsecutiveNeighbours
		page := currentPage - numConsecutiveNeighbours
		for i := consecutiveStart; i <= consecutiveEnd; i++ {
			slots[i] = page
			page += 1
		}
		// The first slot is always the first page.
		slots[0] = 1
		// The last slot is always the last page.
		slots[len(slots)-1] = lastPage
		// Fill in the remaining slots on the left with either an exponentially
		// changing or linearly changing number depending on which is more
		// appropriate.
		remainingSlots := slots[1:consecutiveStart]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := 1; i < consecutiveStart; i++ {
			exponentialNum := currentPage - unit>>shift
			linearNum := currentPage - delta
			if exponentialNum < linearNum && exponentialNum > 1 {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
		// Fill in the remaining slots on the right with either an exponentially
		// changing or linearly changing number depending on which is more
		// appropriate.
		remainingSlots = slots[consecutiveEnd+1 : len(slots)-1]
		delta = numConsecutiveNeighbours + len(remainingSlots)
		shift = 0
		for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
			exponentialNum := currentPage + unit>>shift
			linearNum := currentPage + delta
			if exponentialNum > linearNum && exponentialNum < lastPage {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	}
	// Convert the page numbers in the slots to strings.
	pagination.Numbers = make([]string, len(slots))
	for i, num := range slots {
		pagination.Numbers[i] = strconv.Itoa(num)
	}
	return pagination
}

func (p Pagination) All() []string {
	lastPage, err := strconv.Atoi(p.Last)
	if err != nil {
		return nil
	}
	numbers := make([]string, 0, lastPage)
	for page := 1; page <= lastPage; page++ {
		numbers = append(numbers, strconv.Itoa(page))
	}
	return numbers
}

type AtomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	Xmlns   string      `xml:"xmlns,attr"`
	ID      string      `xml:"id"`
	Title   string      `xml:"title"`
	Updated string      `xml:"updated"`
	Link    []AtomLink  `xml:"link"`
	Entry   []AtomEntry `xml:"entry"`
}

type AtomEntry struct {
	ID        string     `xml:"id"`
	Title     string     `xml:"title"`
	Published string     `xml:"published"`
	Updated   string     `xml:"updated"`
	Link      []AtomLink `xml:"link"`
	Summary   AtomText   `xml:"summary"`
	Content   AtomText   `xml:"content"`
}

type AtomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

type AtomText struct {
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

func (siteGen *SiteGenerator) PostTemplate(ctx context.Context) (*template.Template, error) {
	var err error
	var text sql.NullString
	if remoteFS, ok := siteGen.fsys.(*RemoteFS); ok {
		text, err = sq.FetchOne(ctx, remoteFS.filesDB, sq.Query{
			Dialect: remoteFS.filesDialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("filePath", path.Join(siteGen.sitePrefix, "output/themes/post.html")),
			},
		}, func(row *sq.Row) sql.NullString {
			return row.NullString("text")
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	} else {
		file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "output/themes/post.html"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
		} else {
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				return nil, err
			}
			if fileInfo.IsDir() {
				return nil, fmt.Errorf("%s is not a file", path.Join(siteGen.sitePrefix, "output/themes/post.html"))
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return nil, err
			}
			err = file.Close()
			if err != nil {
				return nil, err
			}
			text = sql.NullString{String: b.String(), Valid: true}
		}
	}
	if !text.Valid {
		file, err := RuntimeFS.Open("embed/post.html")
		if err != nil {
			return nil, err
		}
		fileInfo, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if fileInfo.IsDir() {
			return nil, fmt.Errorf("embed/post.html is not a file")
		}
		var b strings.Builder
		b.Grow(int(fileInfo.Size()))
		_, err = io.Copy(&b, file)
		if err != nil {
			return nil, err
		}
		err = file.Close()
		if err != nil {
			return nil, err
		}
		text = sql.NullString{String: b.String(), Valid: true}
	}
	const doctype = "<!DOCTYPE html>"
	text.String = strings.TrimSpace(text.String)
	if len(text.String) < len(doctype) || !strings.EqualFold(text.String[:len(doctype)], doctype) {
		text.String = "<!DOCTYPE html>" +
			"\n<html lang='{{ $.Site.Lang }}'>" +
			"\n<meta charset='utf-8'>" +
			"\n<meta name='viewport' content='width=device-width, initial-scale=1'>" +
			"\n<link rel='icon' href='{{ $.Site.Favicon }}'>" +
			"\n" + text.String
	}
	tmpl, err := siteGen.ParseTemplate(ctx, "/themes/post.html", text.String, []string{"/themes/post.html"})
	if err != nil {
		return nil, err
	}
	return tmpl, nil
}

func (siteGen *SiteGenerator) PostListTemplate(ctx context.Context, category string) (*template.Template, error) {
	if strings.Contains(category, "/") {
		return nil, ErrInvalidPostCategory
	}
	var err error
	var text sql.NullString
	if remoteFS, ok := siteGen.fsys.(*RemoteFS); ok {
		text, err = sq.FetchOne(ctx, remoteFS.filesDB, sq.Query{
			Dialect: remoteFS.filesDialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("filePath", path.Join(siteGen.sitePrefix, "output/themes/postlist.html")),
			},
		}, func(row *sq.Row) sql.NullString {
			return row.NullString("text")
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	} else {
		file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "output/themes/postlist.html"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
		} else {
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				return nil, err
			}
			if fileInfo.IsDir() {
				return nil, fmt.Errorf("%s is not a file", path.Join(siteGen.sitePrefix, "output/themes/postlist.html"))
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return nil, err
			}
			err = file.Close()
			if err != nil {
				return nil, err
			}
			text = sql.NullString{String: b.String(), Valid: true}
		}
	}
	if !text.Valid {
		file, err := RuntimeFS.Open("embed/postlist.html")
		if err != nil {
			return nil, err
		}
		fileInfo, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if fileInfo.IsDir() {
			return nil, fmt.Errorf("embed/postlist.html is not a file")
		}
		var b strings.Builder
		b.Grow(int(fileInfo.Size()))
		_, err = io.Copy(&b, file)
		if err != nil {
			return nil, err
		}
		err = file.Close()
		if err != nil {
			return nil, err
		}
		text = sql.NullString{String: b.String(), Valid: true}
	}
	const doctype = "<!DOCTYPE html>"
	text.String = strings.TrimSpace(text.String)
	if len(text.String) < len(doctype) || !strings.EqualFold(text.String[:len(doctype)], doctype) {
		text.String = "<!DOCTYPE html>" +
			"\n<html lang='{{ $.Site.Lang }}'>" +
			"\n<meta charset='utf-8'>" +
			"\n<meta name='viewport' content='width=device-width, initial-scale=1'>" +
			"\n<link rel='icon' href='{{ $.Site.Favicon }}'>" +
			"\n<link rel='alternate' href='/" + path.Join("posts", category) + "/index.atom' type='application/atom+xml'>" +
			"\n" + text.String
	}
	tmpl, err := siteGen.ParseTemplate(ctx, "/themes/postlist.html", text.String, []string{"/themes/postlist.html"})
	if err != nil {
		return nil, err
	}
	return tmpl, nil
}
