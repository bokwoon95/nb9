package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bokwoon95/nb9"
	"github.com/bokwoon95/sqddl/ddl"
	"github.com/fsnotify/fsnotify"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type SMTPConfig struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     string `json:"port,omitempty"`
}

type CaptchaConfig struct {
	SecretKey string `json:"secretKey,omitempty"`
	SiteKey   string `json:"siteKey,omitempty"`
}

var (
	open     = func(address string) {}
	startmsg = "Running on %s\n"
)

// static/dynamic private/public config:
// - static private: database.json, dns.json, s3.json, smtp.json (excluded)
// - static public: files.txt domain.txt, contentdomain.txt, multisite.txt
// - dynamic private: captcha.json
// - dynamic public: allowsignup.txt, 503.html

type DatabaseConfig struct {
	Dialect  string            `json:"dialect,omitempty"`
	Filepath string            `json:"filepath,omitempty"`
	User     string            `json:"user,omitempty"`
	Password string            `json:"password,omitempty"`
	Host     string            `json:"host,omitempty"`
	Port     string            `json:"port,omitempty"`
	DBName   string            `json:"dbname,omitempty"`
	Params   map[string]string `json:"params,omitempty"`
}

type S3Config struct {
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	Bucket          string `json:"bucket,omitempty"`
	AccessKeyID     string `json:"accessKeyID,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
}

func main() {
	// Wrap main in anonymous function to honor deferred calls.
	// https://stackoverflow.com/questions/27629380/how-to-exit-a-go-program-honoring-deferred-calls
	err := func() error {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		configHomeDir := os.Getenv("XDG_CONFIG_HOME")
		if configHomeDir == "" {
			configHomeDir = homeDir
		}
		dataHomeDir := os.Getenv("XDG_DATA_HOME")
		if dataHomeDir == "" {
			dataHomeDir = homeDir
		}
		var configDir string
		flagset := flag.NewFlagSet("", flag.ContinueOnError)
		flagset.StringVar(&configDir, "configfolder", "", "")
		err = flagset.Parse(os.Args[1:])
		if err != nil {
			return err
		}
		if configDir == "" {
			configDir = filepath.Join(configHomeDir, "notebrew-config")
			err := os.MkdirAll(configDir, 0755)
			if err != nil {
				return err
			}
		} else {
			configDir = filepath.Clean(configDir)
			_, err := os.Stat(configDir)
			if err != nil {
				return err
			}
		}
		configDir, err = filepath.Abs(filepath.FromSlash(configDir))
		if err != nil {
			return err
		}
		nbrew := &nb9.Notebrew{}
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
		nbrew.Logger.Store(&logger)

		b, err := os.ReadFile(filepath.Join(configDir, "port.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "port.txt"), err)
		}
		port := string(bytes.TrimSpace(b))

		b, err = os.ReadFile(filepath.Join(configDir, "domain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "domain.txt"), err)
		}
		nbrew.Domain = string(bytes.TrimSpace(b))

		var addr string
		if port != "" {
			if nbrew.Domain == "" {
				nbrew.Domain = "localhost:" + port
			}
			if port == "443" || port == "80" {
				addr = ":" + port
			} else {
				addr = "localhost:" + port
			}
		} else {
			if nbrew.Domain == "" {
				nbrew.Domain = "localhost:6444"
				addr = "localhost:6444"
			} else {
				addr = ":443"
			}
		}

		b, err = os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "contentdomain.txt"), err)
		}
		nbrew.ContentDomain = string(bytes.TrimSpace(b))
		if nbrew.ContentDomain == "" {
			nbrew.ContentDomain = nbrew.Domain
		}

		b, err = os.ReadFile(filepath.Join(configDir, "database.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
		}
		b = bytes.TrimSpace(b)
		if len(b) > 0 {
			var databaseConfig DatabaseConfig
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&databaseConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
			}
			switch databaseConfig.Dialect {
			case "":
				return fmt.Errorf("%s: missing dialect field", filepath.Join(configDir, "database.json"))
			case "sqlite":
				if databaseConfig.Filepath == "" {
					databaseConfig.Filepath = filepath.Join(dataHomeDir, "notebrew-database.sqlite")
				}
				databaseConfig.Filepath, err = filepath.Abs(databaseConfig.Filepath)
				if err != nil {
					return fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "database.json"), err)
				}
				dataSourceName := databaseConfig.Filepath + "?" + sqliteQueryString(databaseConfig.Params)
				nbrew.Dialect = "sqlite"
				nbrew.DB, err = sql.Open(sqliteDriverName, dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
				}
				err = nbrew.DB.Ping()
				if err != nil {
					return fmt.Errorf("%s: sqlite: ping %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
				}
				automigrateCmd := &ddl.AutomigrateCmd{
					DB:             nbrew.DB,
					Dialect:        nbrew.Dialect,
					DestCatalog:    nb9.Catalog(nbrew.Dialect),
					DropObjects:    true, // TODO: turn this off when we go live.
					AcceptWarnings: true,
					Stderr:         io.Discard,
				}
				err = automigrateCmd.Run()
				if err != nil {
					return err
				}
			case "postgres":
				values := make(url.Values)
				for key, value := range databaseConfig.Params {
					switch key {
					case "sslmode":
						values.Set(key, value)
					}
				}
				if _, ok := databaseConfig.Params["sslmode"]; !ok {
					values.Set("sslmode", "disable")
				}
				if databaseConfig.Port == "" {
					databaseConfig.Port = "5432"
				}
				uri := url.URL{
					Scheme:   "postgres",
					User:     url.UserPassword(databaseConfig.User, databaseConfig.Password),
					Host:     databaseConfig.Host + ":" + databaseConfig.Port,
					Path:     databaseConfig.DBName,
					RawQuery: values.Encode(),
				}
				dataSourceName := uri.String()
				nbrew.Dialect = "postgres"
				nbrew.DB, err = sql.Open("pgx", dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
				}
				err = nbrew.DB.Ping()
				if err != nil {
					return fmt.Errorf("%s: postgres: ping %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
				}
				nbrew.ErrorCode = func(err error) string {
					var pgErr *pgconn.PgError
					if errors.As(err, &pgErr) {
						return pgErr.Code
					}
					return ""
				}
				automigrateCmd := &ddl.AutomigrateCmd{
					DB:             nbrew.DB,
					Dialect:        nbrew.Dialect,
					DestCatalog:    nb9.Catalog(nbrew.Dialect),
					DropObjects:    true, // TODO: turn this off when we go live.
					AcceptWarnings: true,
					Stderr:         io.Discard,
				}
				err = automigrateCmd.Run()
				if err != nil {
					return err
				}
			case "mysql":
				values := make(url.Values)
				for key, value := range databaseConfig.Params {
					switch key {
					case "charset", "collation", "loc", "maxAllowedPacket",
						"readTimeout", "rejectReadOnly", "serverPubKey", "timeout",
						"tls", "writeTimeout", "connectionAttributes":
						values.Set(key, value)
					}
				}
				values.Set("multiStatements", "true")
				values.Set("parseTime", "true")
				if databaseConfig.Port == "" {
					databaseConfig.Port = "3306"
				}
				config, err := mysql.ParseDSN(fmt.Sprintf("tcp(%s:%s)/%s?%s", databaseConfig.Host, databaseConfig.Port, url.PathEscape(databaseConfig.DBName), values.Encode()))
				if err != nil {
					return err
				}
				// Set user and passwd manually to accomodate special characters.
				// https://github.com/go-sql-driver/mysql/issues/1323
				config.User = databaseConfig.User
				config.Passwd = databaseConfig.Password
				driver, err := mysql.NewConnector(config)
				if err != nil {
					return err
				}
				nbrew.Dialect = "mysql"
				nbrew.DB = sql.OpenDB(driver)
				if err != nil {
					return fmt.Errorf("%s: mysql: open %s: %w", filepath.Join(configDir, "database.json"), config.FormatDSN(), err)
				}
				err = nbrew.DB.Ping()
				if err != nil {
					return fmt.Errorf("%s: mysql: ping %s: %w", filepath.Join(configDir, "database.json"), config.FormatDSN(), err)
				}
				nbrew.ErrorCode = func(err error) string {
					var mysqlErr *mysql.MySQLError
					if errors.As(err, &mysqlErr) {
						return strconv.FormatUint(uint64(mysqlErr.Number), 10)
					}
					return ""
				}
				automigrateCmd := &ddl.AutomigrateCmd{
					DB:             nbrew.DB,
					Dialect:        nbrew.Dialect,
					DestCatalog:    nb9.Catalog(nbrew.Dialect),
					DropObjects:    true, // TODO: turn this off when we go live.
					AcceptWarnings: true,
					Stderr:         io.Discard,
				}
				err = automigrateCmd.Run()
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "database.json"), databaseConfig.Dialect)
			}
			err = nb9.Automigrate(nbrew.Dialect, nbrew.DB)
			if err != nil {
				return err
			}
			defer func() {
				if nbrew.Dialect == "sqlite" {
					nbrew.DB.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
				}
				nbrew.DB.Close()
			}()
		}

		b, err = os.ReadFile(filepath.Join(configDir, "files.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
		}
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			b = []byte("{}")
		}
		var filesConfig DatabaseConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&filesConfig)
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
		}
		switch filesConfig.Dialect {
		case "":
			if filesConfig.Filepath == "" {
				filesConfig.Filepath = filepath.Join(dataHomeDir, "notebrew-files")
				err := os.MkdirAll(filesConfig.Filepath, 0755)
				if err != nil {
					return err
				}
			} else {
				filesConfig.Filepath = filepath.Clean(filesConfig.Filepath)
				_, err := os.Stat(filesConfig.Filepath)
				if err != nil {
					return err
				}
			}
			nbrew.FS = nb9.NewLocalFS(nb9.LocalFSConfig{
				RootDir: filesConfig.Filepath,
				TempDir: os.TempDir(),
			})
		case "sqlite":
			if filesConfig.Filepath == "" {
				filesConfig.Filepath = filepath.Join(dataHomeDir, "notebrew-files.sqlite")
			}
			filesConfig.Filepath, err = filepath.Abs(filesConfig.Filepath)
			if err != nil {
				return fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "files.json"), err)
			}
			dataSourceName := filesConfig.Filepath + "?" + sqliteQueryString(filesConfig.Params)
			filesDialect := "sqlite"
			filesDB, err := sql.Open(sqliteDriverName, dataSourceName)
			if err != nil {
				return fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
			}
			err = filesDB.Ping()
			if err != nil {
				return fmt.Errorf("%s: sqlite: ping %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
			}
			_, _ = filesDialect, filesDB
		case "postgres":
			values := make(url.Values)
			for key, value := range filesConfig.Params {
				switch key {
				case "sslmode":
					values.Set(key, value)
				}
			}
			if _, ok := filesConfig.Params["sslmode"]; !ok {
				values.Set("sslmode", "disable")
			}
			if filesConfig.Port == "" {
				filesConfig.Port = "5432"
			}
			uri := url.URL{
				Scheme:   "postgres",
				User:     url.UserPassword(filesConfig.User, filesConfig.Password),
				Host:     filesConfig.Host + ":" + filesConfig.Port,
				Path:     filesConfig.DBName,
				RawQuery: values.Encode(),
			}
			dataSourceName := uri.String()
			filesDialect := "postgres"
			filesDB, err := sql.Open("pgx", dataSourceName)
			if err != nil {
				return fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
			}
			err = filesDB.Ping()
			if err != nil {
				return fmt.Errorf("%s: postgres: ping %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
			}
		case "mysql":
			values := make(url.Values)
			for key, value := range filesConfig.Params {
				switch key {
				case "charset", "collation", "loc", "maxAllowedPacket",
					"readTimeout", "rejectReadOnly", "serverPubKey", "timeout",
					"tls", "writeTimeout", "connectionAttributes":
					values.Set(key, value)
				}
			}
			values.Set("multiStatements", "true")
			values.Set("parseTime", "true")
			if filesConfig.Port == "" {
				filesConfig.Port = "3306"
			}
			config, err := mysql.ParseDSN(fmt.Sprintf("tcp(%s:%s)/%s?%s", filesConfig.Host, filesConfig.Port, url.PathEscape(filesConfig.DBName), values.Encode()))
			if err != nil {
				return err
			}
			// Set user and passwd manually to accomodate special characters.
			// https://github.com/go-sql-driver/mysql/issues/1323
			config.User = filesConfig.User
			config.Passwd = filesConfig.Password
			driver, err := mysql.NewConnector(config)
			if err != nil {
				return err
			}
			nbrew.Dialect = "mysql"
			nbrew.DB = sql.OpenDB(driver)
			if err != nil {
				return fmt.Errorf("%s: mysql: open %s: %w", filepath.Join(configDir, "database.json"), config.FormatDSN(), err)
			}
			err = nbrew.DB.Ping()
			if err != nil {
				return fmt.Errorf("%s: mysql: ping %s: %w", filepath.Join(configDir, "database.json"), config.FormatDSN(), err)
			}
			nbrew.ErrorCode = func(err error) string {
				var mysqlErr *mysql.MySQLError
				if errors.As(err, &mysqlErr) {
					return strconv.FormatUint(uint64(mysqlErr.Number), 10)
				}
				return ""
			}
		default:
			return fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "database.json"), filesConfig.Dialect)
		}
		err = nb9.Automigrate(nbrew.Dialect, nbrew.DB)
		if err != nil {
			return err
		}
		defer func() {
			if nbrew.Dialect == "sqlite" {
				nbrew.DB.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
			}
			nbrew.DB.Close()
		}()
		filesfolder := string(bytes.TrimSpace(b))
		if filesfolder == "" {
			filesfolder = filepath.Join(dataHomeDir, "notebrew-files")
			err := os.MkdirAll(filesfolder, 0755)
			if err != nil {
				return err
			}
			nbrew.FS = nb9.NewLocalFS(filesfolder, os.TempDir())
		} else if filesfolder == "database" {
			if nbrew.DB == nil {
				return fmt.Errorf("%s: cannot use database as filesystem because %s is missing", filepath.Join(configDir, "files.txt"), filepath.Join(configDir, "database.json"))
			}
			b, err = os.ReadFile(filepath.Join(configDir, "s3.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "s3.json"), err)
			}
			b = bytes.TrimSpace(b)
			if len(b) > 0 {
				var s3Config struct {
					Endpoint        string `json:"endpoint,omitempty"`
					Region          string `json:"region,omitempty"`
					Bucket          string `json:"bucket,omitempty"`
					AccessKeyID     string `json:"accessKeyID,omitempty"`
					SecretAccessKey string `json:"secretAccessKey,omitempty"`
				}
				decoder := json.NewDecoder(bytes.NewReader(b))
				decoder.DisallowUnknownFields()
				err := decoder.Decode(&s3Config)
				if err != nil {
					return fmt.Errorf("%s: %w", filepath.Join(configDir, "s3.json"), err)
				}
				if s3Config.Endpoint == "" {
					return fmt.Errorf("%s: missing endpoint field", filepath.Join(configDir, "s3.json"))
				}
				if s3Config.Region == "" {
					return fmt.Errorf("%s: missing region field", filepath.Join(configDir, "s3.json"))
				}
				if s3Config.Bucket == "" {
					return fmt.Errorf("%s: missing bucket field", filepath.Join(configDir, "s3.json"))
				}
				if s3Config.AccessKeyID == "" {
					return fmt.Errorf("%s: missing accessKeyID field", filepath.Join(configDir, "s3.json"))
				}
				if s3Config.SecretAccessKey == "" {
					return fmt.Errorf("%s: missing secretAccessKey field", filepath.Join(configDir, "s3.json"))
				}
				nbrew.FS = nb9.NewRemoteFS(nbrew.Dialect, nbrew.DB, nbrew.ErrorCode, &nb9.S3Storage{
					Client: s3.New(s3.Options{
						BaseEndpoint: aws.String(s3Config.Endpoint),
						Region:       s3Config.Region,
						Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(s3Config.AccessKeyID, s3Config.SecretAccessKey, "")),
					}),
					Bucket: s3Config.Bucket,
				}, "", nil)
			} else {
				b, err = os.ReadFile(filepath.Join(configDir, "objectsfolder.txt"))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("%s: %w", filepath.Join(configDir, "objectsfolder.txt"), err)
				}
				objectsDir := string(bytes.TrimSpace(b))
				if objectsDir == "" {
					objectsDir = filepath.Join(dataHomeDir, "notebrew-objects")
					err := os.MkdirAll(objectsDir, 0755)
					if err != nil {
						return err
					}
				} else {
					objectsDir = path.Clean(objectsDir)
					_, err := os.Stat(objectsDir)
					if err != nil {
						return err
					}
				}
				nbrew.FS = nb9.NewRemoteFS(nbrew.Dialect, nbrew.DB, nbrew.ErrorCode, nb9.NewFileStorage(objectsDir, os.TempDir()), "", nil)
			}
		} else {
			filesfolder = filepath.Clean(filesfolder)
			_, err := os.Stat(filesfolder)
			if err != nil {
				return err
			}
			nbrew.FS = nb9.NewLocalFS(filesfolder, os.TempDir())
		}
		dirs := []string{
			"notes",
			"output",
			"output/posts",
			"output/themes",
			"pages",
			"posts",
		}
		for _, dir := range dirs {
			err = nbrew.FS.Mkdir(dir, 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		}

		reloadableFiles := map[string]func(nbrew *nb9.Notebrew, configfolder string) error{
			"gzipgeneratedcontent.txt": func(nbrew *nb9.Notebrew, configfolder string) error {
				b, err := os.ReadFile(filepath.Join(configfolder, "gzipgeneratedcontent.txt"))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
				}
				gzipGeneratedContent, _ := strconv.ParseBool(string(b))
				nbrew.GzipGeneratedContent.Store(gzipGeneratedContent)
				return nil
			},
		}
		for name, reloadFunc := range reloadableFiles {
			err := reloadFunc(nbrew, configDir)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, name), err)
			}
		}

		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return err
		}
		defer watcher.Close()
		err = watcher.Add(configDir)
		if err != nil {
			return err
		}
		timer := time.NewTimer(0)
		timer.Stop()
		go func() {
			for {
				select {
				case err := <-watcher.Errors:
					fmt.Println(err)
				case event := <-watcher.Events:
					if event.Op == fsnotify.Chmod {
						continue
					}
					timer.Reset(500 * time.Millisecond)
				case <-timer.C:
					timestamp := time.Now().UTC().Format("2006-01-02 15:04:05Z")
					for name, reloadFunc := range reloadableFiles {
						err := reloadFunc(nbrew, configDir)
						if err != nil {
							fmt.Printf("%s: reloading %s: %s", timestamp, filepath.Join(configDir, name), err)
						}
					}
				}
			}
		}()

		// TODO:
		// go install github.com/notebrew/notebrew/notebrew
		// irm github.com/notebrew/notebrew/install.cmd | iex
		// curl github.com/notebrew/notebrew/install.sh | sh

		args := flagset.Args()
		if len(args) > 0 {
			command, args := args[0], args[1:]
			_ = args
			switch command {
			case "":
			default:
				return fmt.Errorf("unknown command %s", command)
			}
			return nil
		}

		server, err := NewServer(nbrew, configDir, addr)
		if err != nil {
			return err
		}

		// Manually acquire a listener instead of using the more convenient
		// ListenAndServe() just so that we can report back to the user if the
		// port is already in use.
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			var errno syscall.Errno
			if !errors.As(err, &errno) {
				return err
			}
			// WSAEADDRINUSE copied from
			// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
			// To avoid importing an entire 3rd party library just to use a constant.
			const WSAEADDRINUSE = syscall.Errno(10048)
			if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
				if server.Addr == "localhost" || strings.HasPrefix(server.Addr, "localhost:") {
					fmt.Println("notebrew is already running on http://" + server.Addr + "/files/")
					open("http://" + server.Addr + "/files/")
					return nil
				}
				// TODO: don't assume notebrew is already running, in this path SIGHUP will end the process so the server is unlikely to be running
				fmt.Println("notebrew is already running (run `notebrew stop` to stop the process)")
				return nil
			}
			return err
		}

		// Swallow SIGHUP so that we can keep running even when the (SSH)
		// session ends (the user should use `notebrew stop` to stop the
		// process).
		// ch := make(chan os.Signal, 1)
		// signal.Notify(ch, syscall.SIGHUP)
		// go func() {
		// 	for {
		// 		<-ch
		// 	}
		// }()

		wait := make(chan os.Signal, 1)
		signal.Notify(wait, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		if server.Addr == ":443" {
			go func() {
				err := server.ServeTLS(listener, "", "")
				if !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			go http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" && r.Method != "HEAD" {
					http.Error(w, "Use HTTPS", http.StatusBadRequest)
					return
				}
				host, _, err := net.SplitHostPort(r.Host)
				if err != nil {
					host = r.Host
				} else {
					host = net.JoinHostPort(host, "443")
				}
				http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
			}))
			fmt.Printf(startmsg, server.Addr)
		} else {
			go func() {
				err := server.Serve(listener)
				if !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			if server.Addr == "localhost" || strings.HasPrefix(server.Addr, "localhost:") {
				fmt.Printf(startmsg, "http://"+server.Addr+"/files/")
				open("http://" + server.Addr + "/files/")
			}
		}
		<-wait
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		server.Shutdown(ctx)
		return nil
	}()
	if err != nil && !errors.Is(err, flag.ErrHelp) && !errors.Is(err, io.EOF) {
		fmt.Println(err)
		pressAnyKeyToExit()
		os.Exit(1)
	}
}
