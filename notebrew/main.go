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
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type SMTPConfig struct {
	Username string
	Password string
	Host     string
	Port     string
}

type CaptchaConfig struct {
	SecretKey string
	SiteKey   string
}

var (
	open     = func(address string) {}
	startmsg = "Running on %s\n"
)

// static/dynamic private/public config:
// - static private: users.json, dns.json, s3.json, smtp.json (excluded)
// - static public: files.txt cmsdomain.txt, contentdomain.txt, multisite.txt
// - dynamic private: captcha.json
// - dynamic public: allowsignup.txt, 503.html

func main() {
	// Wrap main in anonymous function to honor deferred calls.
	// https://stackoverflow.com/questions/27629380/how-to-exit-a-go-program-honoring-deferred-calls
	err := func() error {
		// homeDir is the user's home directory.
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		// configHomeDir is the user's config directory.
		configHomeDir := os.Getenv("XDG_CONFIG_HOME")
		if configHomeDir == "" {
			configHomeDir = homeDir
		}
		// dataHomeDir is the user's data directory.
		dataHomeDir := os.Getenv("XDG_DATA_HOME")
		if dataHomeDir == "" {
			dataHomeDir = homeDir
		}
		// configDir is notebrew's configuration directory.
		var configDir string
		flagset := flag.NewFlagSet("", flag.ContinueOnError)
		flagset.StringVar(&configDir, "configdir", "", "")
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
		nbrew := &nb9.Notebrew{
			Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				AddSource: true,
			})),
		}

		// CMS domain.
		b, err := os.ReadFile(filepath.Join(configDir, "cmsdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "cmsdomain.txt"), err)
		}
		nbrew.CMSDomain = string(bytes.TrimSpace(b))

		// Determine the port to listen on (can be empty).
		b, err = os.ReadFile(filepath.Join(configDir, "port.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "port.txt"), err)
		}
		port := string(bytes.TrimSpace(b))

		// Determine the TCP address to listen on (based on the domain and port).
		var addr string
		if port != "" {
			if nbrew.CMSDomain == "" {
				nbrew.CMSDomain = "localhost:" + port
			}
			if port == "443" || port == "80" {
				addr = ":" + port
			} else {
				addr = "localhost:" + port
			}
		} else {
			if nbrew.CMSDomain == "" {
				nbrew.CMSDomain = "localhost:6444"
				addr = "localhost:6444"
			} else {
				addr = ":443"
			}
		}

		// Content domain.
		b, err = os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "contentdomain.txt"), err)
		}
		nbrew.ContentDomain = string(bytes.TrimSpace(b))
		if nbrew.ContentDomain == "" {
			nbrew.ContentDomain = nbrew.CMSDomain
		}

		// Img domain.
		b, err = os.ReadFile(filepath.Join(configDir, "imgdomain.txt"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "imgdomain.txt"), err)
			}
		} else {
			nbrew.ImgDomain = string(bytes.TrimSpace(b))
		}

		b, err = os.ReadFile(filepath.Join(configDir, "database.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
		}
		b = bytes.TrimSpace(b)
		if len(b) > 0 {
			var databaseConfig struct {
				Dialect  string
				Filepath string
				User     string
				Password string
				Host     string
				Port     string
				DBName   string
				Params   map[string]string
			}
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&databaseConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
			}
			var dataSourceName string
			switch databaseConfig.Dialect {
			case "":
				return fmt.Errorf("%s: missing dialect field", filepath.Join(configDir, "database.json"))
			case "sqlite":
				if databaseConfig.Filepath == "" {
					databaseConfig.Filepath = filepath.Join(dataHomeDir, "notebrew-users.db")
				}
				databaseConfig.Filepath, err = filepath.Abs(databaseConfig.Filepath)
				if err != nil {
					return fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "database.json"), err)
				}
				dataSourceName = databaseConfig.Filepath + "?" + sqliteQueryString(databaseConfig.Params)
				nbrew.Dialect = "sqlite"
				nbrew.DB, err = sql.Open(sqliteDriverName, dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
				}
				nbrew.ErrorCode = sqliteErrorCode
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
				dataSourceName = uri.String()
				nbrew.Dialect = "postgres"
				nbrew.DB, err = sql.Open("pgx", dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
				}
				nbrew.ErrorCode = func(err error) string {
					var pgErr *pgconn.PgError
					if errors.As(err, &pgErr) {
						return pgErr.Code
					}
					return ""
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
				dataSourceName = config.FormatDSN()
				nbrew.Dialect = "mysql"
				nbrew.DB = sql.OpenDB(driver)
				nbrew.ErrorCode = func(err error) string {
					var mysqlErr *mysql.MySQLError
					if errors.As(err, &mysqlErr) {
						return strconv.FormatUint(uint64(mysqlErr.Number), 10)
					}
					return ""
				}
			default:
				return fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "database.json"), databaseConfig.Dialect)
			}

			if err != nil {
				return fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "database.json"), nbrew.Dialect, dataSourceName, err)
			}
			usersCatalog, err := nb9.UsersCatalog(nbrew.Dialect)
			if err != nil {
				return err
			}
			automigrateCmd := &ddl.AutomigrateCmd{
				DB:             nbrew.DB,
				Dialect:        nbrew.Dialect,
				DestCatalog:    usersCatalog,
				DropObjects:    true, // TODO: turn this off when we go live.
				AcceptWarnings: true,
				Stderr:         io.Discard,
			}
			err = automigrateCmd.Run()
			if err != nil {
				return err
			}
			defer func() {
				if nbrew.Dialect == "sqlite" {
					nbrew.DB.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
				}
				ticker := time.NewTicker(4 * time.Hour)
				go func() {
					for {
						<-ticker.C
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						_, err = nbrew.DB.ExecContext(ctx, "PRAGMA analysis_limit(400); PRAGMA optimize;")
						if err != nil {
							nbrew.Logger.Error(err.Error())
						}
						cancel()
					}
				}()
				nbrew.DB.Close()
			}()
		}

		b, err = os.ReadFile(filepath.Join(configDir, "files.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
		}
		b = bytes.TrimSpace(b)
		var filesConfig struct {
			Dialect  string
			Filepath string
			User     string
			Password string
			Host     string
			Port     string
			DBName   string
			Params   map[string]string
		}
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&filesConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
			}
		}
		if filesConfig.Dialect == "" {
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
			nbrew.FS, err = nb9.NewLocalFS(nb9.LocalFSConfig{
				RootDir: filesConfig.Filepath,
				TempDir: os.TempDir(),
			})
			if err != nil {
				return err
			}
		} else {
			var dataSourceName string
			var dialect string
			var db *sql.DB
			var errorCode func(error) string
			switch filesConfig.Dialect {
			case "sqlite":
				if filesConfig.Filepath == "" {
					filesConfig.Filepath = filepath.Join(dataHomeDir, "notebrew-files.db")
				}
				filesConfig.Filepath, err = filepath.Abs(filesConfig.Filepath)
				if err != nil {
					return fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "files.json"), err)
				}
				dataSourceName = filesConfig.Filepath + "?" + sqliteQueryString(filesConfig.Params)
				dialect = "sqlite"
				db, err = sql.Open(sqliteDriverName, dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
				}
				errorCode = sqliteErrorCode
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
				dataSourceName = uri.String()
				dialect = "postgres"
				db, err = sql.Open("pgx", dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
				}
				errorCode = func(err error) string {
					var pgErr *pgconn.PgError
					if errors.As(err, &pgErr) {
						return pgErr.Code
					}
					return ""
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
				dataSourceName = config.FormatDSN()
				dialect = "mysql"
				db = sql.OpenDB(driver)
				errorCode = func(err error) string {
					var mysqlErr *mysql.MySQLError
					if errors.As(err, &mysqlErr) {
						return strconv.FormatUint(uint64(mysqlErr.Number), 10)
					}
					return ""
				}
			default:
				return fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "database.json"), filesConfig.Dialect)
			}
			err = db.Ping()
			if err != nil {
				return fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "database.json"), dialect, dataSourceName, err)
			}
			filesCatalog, err := nb9.FilesCatalog(dialect)
			if err != nil {
				return err
			}
			automigrateCmd := &ddl.AutomigrateCmd{
				DB:             db,
				Dialect:        dialect,
				DestCatalog:    filesCatalog,
				DropObjects:    true, // TODO: turn this off when we go live.
				AcceptWarnings: true,
				Stderr:         io.Discard,
			}
			err = automigrateCmd.Run()
			if err != nil {
				return err
			}
			if dialect == "sqlite" {
				dbi := ddl.NewDatabaseIntrospector(dialect, db)
				dbi.Tables = []string{"files_fts5"}
				tables, err := dbi.GetTables()
				if err != nil {
					return err
				}
				if len(tables) == 0 {
					_, err := db.Exec("CREATE VIRTUAL TABLE files_fts5 USING fts5 (text, content=files);")
					if err != nil {
						return err
					}
				}
				dbi.Tables = []string{"files"}
				triggers, err := dbi.GetTriggers()
				if err != nil {
					return err
				}
				triggerNames := make(map[string]struct{})
				for _, trigger := range triggers {
					triggerNames[trigger.TriggerName] = struct{}{}
				}
				if _, ok := triggerNames["files_after_insert"]; !ok {
					_, err := db.Exec("CREATE TRIGGER files_after_insert AFTER INSERT ON files BEGIN" +
						"\n    INSERT INTO files_fts5 (rowid, text) VALUES (NEW.rowid, NEW.text);" +
						"\nEND;",
					)
					if err != nil {
						return err
					}
				}
				if _, ok := triggerNames["files_after_delete"]; !ok {
					_, err := db.Exec("CREATE TRIGGER files_after_delete AFTER DELETE ON files BEGIN" +
						"\n    INSERT INTO files_fts5 (files_fts5, rowid, text) VALUES ('delete', OLD.rowid, OLD.text);" +
						"\nEND;",
					)
					if err != nil {
						return err
					}
				}
				if _, ok := triggerNames["files_after_update"]; !ok {
					_, err := db.Exec("CREATE TRIGGER files_after_update AFTER UPDATE ON files BEGIN" +
						"\n    INSERT INTO files_fts5 (files_fts5, rowid, text) VALUES ('delete', OLD.rowid, OLD.text);" +
						"\n    INSERT INTO files_fts5 (rowid, text) VALUES (NEW.rowid, NEW.text);" +
						"\nEND;",
					)
					if err != nil {
						return err
					}
				}
			}
			defer func() {
				if dialect == "sqlite" {
					db.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
				}
				ticker := time.NewTicker(4 * time.Hour)
				go func() {
					for {
						<-ticker.C
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						_, err = db.ExecContext(ctx, "PRAGMA analysis_limit(400); PRAGMA optimize;")
						if err != nil {
							nbrew.Logger.Error(err.Error())
						}
						cancel()
					}
				}()
				db.Close()
			}()

			var storage nb9.Storage
			b, err = os.ReadFile(filepath.Join(configDir, "s3.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "s3.json"), err)
			}
			b = bytes.TrimSpace(b)
			if len(b) > 0 {
				var s3Config struct {
					Endpoint        string
					Region          string
					Bucket          string
					AccessKeyID     string
					SecretAccessKey string
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
				storage = &nb9.S3Storage{
					Client: s3.New(s3.Options{
						BaseEndpoint: aws.String(s3Config.Endpoint),
						Region:       s3Config.Region,
						Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(s3Config.AccessKeyID, s3Config.SecretAccessKey, "")),
					}),
					Bucket: s3Config.Bucket,
				}
			} else {
				b, err = os.ReadFile(filepath.Join(configDir, "objectsdir.txt"))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("%s: %w", filepath.Join(configDir, "objectsdir.txt"), err)
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
				storage = nb9.NewLocalStorage(objectsDir, os.TempDir())
			}
			nbrew.FS, err = nb9.NewRemoteFS(nb9.RemoteFSConfig{
				DB:        db,
				Dialect:   dialect,
				ErrorCode: errorCode,
				Storage:   storage,
				Logger:    nbrew.Logger,
			})
			if err != nil {
				return err
			}
		}
		for _, dir := range []string{
			"notes",
			"output",
			"output/posts",
			"output/themes",
			"pages",
			"posts",
		} {
			err = nbrew.FS.Mkdir(dir, 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		}
		siteGen, err := nb9.NewSiteGenerator(context.Background(), nbrew.FS, "", nbrew.ContentDomain, nbrew.ImgDomain)
		if err != nil {
			return err
		}
		_, err = fs.Stat(nbrew.FS, "pages/index.html")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			b, err := fs.ReadFile(nb9.RuntimeFS, "embed/index.html")
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter("pages/index.html", 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			err = siteGen.GeneratePage(context.Background(), "pages/index.html", string(b))
			if err != nil {
				return err
			}
		}
		_, err = fs.Stat(nbrew.FS, "pages/404.html")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			b, err := fs.ReadFile(nb9.RuntimeFS, "embed/404.html")
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter("pages/404.html", 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			err = siteGen.GeneratePage(context.Background(), "pages/404.html", string(b))
			if err != nil {
				return err
			}
		}
		_, err = fs.Stat(nbrew.FS, "output/themes/post.html")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			b, err := fs.ReadFile(nb9.RuntimeFS, "embed/post.html")
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter("output/themes/post.html", 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
		}
		_, err = fs.Stat(nbrew.FS, "output/themes/postlist.html")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			b, err := fs.ReadFile(nb9.RuntimeFS, "embed/postlist.html")
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter("output/themes/postlist.html", 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			tmpl, err := siteGen.PostListTemplate(context.Background(), "")
			if err != nil {
				return err
			}
			_, err = siteGen.GeneratePostList(context.Background(), "", tmpl)
			if err != nil {
				return err
			}
		}

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
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
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
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			if server.Addr == "localhost" || strings.HasPrefix(server.Addr, "localhost:") {
				fmt.Printf(startmsg, "http://"+server.Addr+"/files/")
				open("http://" + server.Addr + "/files/")
			} else {
				fmt.Printf(startmsg, server.Addr)
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
