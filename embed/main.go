package main

import (
	"bytes"
	_ "embed"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"strings"

	"golang.org/x/net/html"
)

//go:embed test_input.html
var testInput []byte

func main() {
	reader := bytes.NewReader(testInput)
	// writer, err := os.OpenFile("test_output.html", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer writer.Close()
	writer := os.Stdout
	pipeReader, pipeWriter := io.Pipe()
	result := make(chan error, 1)
	go func() {
		const escapedChars = "&'<>\"\r"
		tokenizer := html.NewTokenizer(pipeReader)
		for {
			tokenType := tokenizer.Next()
			switch tokenType {
			case html.ErrorToken:
				err := tokenizer.Err()
				if err != io.EOF {
					result <- err
					return
				}
				result <- writer.Close()
				return
			case html.TextToken:
				_, err := writer.Write(tokenizer.Text())
				if err != nil {
					result <- err
					return
				}
			case html.DoctypeToken:
				_, err := writer.Write([]byte("<!DOCTYPE "))
				if err != nil {
					result <- err
					return
				}
				_, err = writer.Write(tokenizer.Text())
				if err != nil {
					result <- err
					return
				}
				_, err = writer.Write([]byte(">"))
				if err != nil {
					result <- err
					return
				}
			case html.CommentToken:
				_, err := writer.Write([]byte("<!--"))
				if err != nil {
					result <- err
					return
				}
				_, err = writer.Write(tokenizer.Text())
				if err != nil {
					result <- err
					return
				}
				_, err = writer.Write([]byte("-->"))
				if err != nil {
					result <- err
					return
				}
			case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
				switch tokenType {
				case html.StartTagToken, html.SelfClosingTagToken:
					_, err := writer.Write([]byte("<"))
					if err != nil {
						result <- err
						return
					}
				case html.EndTagToken:
					_, err := writer.Write([]byte("</"))
					if err != nil {
						result <- err
						return
					}
				}
				var key, val []byte
				name, moreAttr := tokenizer.TagName()
				_, err := writer.Write(name)
				if err != nil {
					result <- err
					return
				}
				for moreAttr {
					key, val, moreAttr = tokenizer.TagAttr()
					_, err := writer.Write([]byte(" "))
					if err != nil {
						result <- err
						return
					}
					_, err = writer.Write(key)
					if err != nil {
						result <- err
						return
					}
					_, err = writer.Write([]byte("=\""))
					if err != nil {
						result <- err
						return
					}
					if bytes.Equal(name, []byte("img")) && bytes.Equal(key, []byte("src")) {
						uri, err := url.Parse(string(val))
						if err == nil && uri.Scheme == "" && uri.Host == "" {
							switch path.Ext(uri.Path) {
							case ".jpeg", ".jpg", ".png", ".webp", ".gif":
								uri.Scheme = "https"
								uri.Host = "cdn.nbrew.io"
								if !strings.HasPrefix(uri.Path, "/") {
									uri.Path = "/rel/path/to/page/" + uri.Path
								}
								val = []byte(uri.String())
							}
						}
					}
					_, err = writer.Write(val)
					if err != nil {
						result <- err
						return
					}
					_, err = writer.Write([]byte("\""))
					if err != nil {
						result <- err
						return
					}
				}
				switch tokenType {
				case html.StartTagToken, html.EndTagToken:
					_, err = writer.Write([]byte(">"))
					if err != nil {
						result <- err
						return
					}
				case html.SelfClosingTagToken:
					_, err = writer.Write([]byte("/>"))
					if err != nil {
						result <- err
						return
					}
				}
			}
		}
	}()
	_, err := io.Copy(pipeWriter, reader)
	if err != nil {
		log.Fatal(err)
	}
	pipeWriter.Close()
	err = <-result
	if err != nil {
		log.Fatal(err)
	}
}
