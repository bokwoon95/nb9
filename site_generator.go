package nb9

import (
	"fmt"
	"html/template"
	"io/fs"
	"path"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"
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
	// TODO: eventually make these configurable
	postsPerPage map[string]int // default 100
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
	siteGen.fsys.ScanDir(path.Join(siteGen.sitePrefix, "posts"), func(dirEntry fs.DirEntry) error {
		if dirEntry.IsDir() {
			siteGen.site.Categories = append(siteGen.site.Categories, dirEntry.Name())
		}
		return nil
	})
	return siteGen, nil
}
