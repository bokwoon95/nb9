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

type DatabaseConfig struct {
	Dialect  string
	Filepath string
	User     string
	Password string
	Host     string
	Port     string
	DBName   string
	Params   map[string]string
}

type S3Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
}

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
		nbrew := &nb9.Notebrew{}
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
		nbrew.Logger.Store(&logger)

		// Determine the domain.
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

		// Determine the content domain.
		b, err = os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "contentdomain.txt"), err)
		}
		nbrew.ContentDomain = string(bytes.TrimSpace(b))
		if nbrew.ContentDomain == "" {
			nbrew.ContentDomain = nbrew.CMSDomain
		}

		b, err = os.ReadFile(filepath.Join(configDir, "users.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "users.json"), err)
		}
		b = bytes.TrimSpace(b)
		if len(b) > 0 {
			var databaseConfig DatabaseConfig
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&databaseConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "users.json"), err)
			}
			var dataSourceName string
			switch databaseConfig.Dialect {
			case "":
				return fmt.Errorf("%s: missing dialect field", filepath.Join(configDir, "users.json"))
			case "sqlite":
				if databaseConfig.Filepath == "" {
					databaseConfig.Filepath = filepath.Join(dataHomeDir, "notebrew-users.db")
				}
				databaseConfig.Filepath, err = filepath.Abs(databaseConfig.Filepath)
				if err != nil {
					return fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "users.json"), err)
				}
				dataSourceName = databaseConfig.Filepath + "?" + sqliteQueryString(databaseConfig.Params)
				nbrew.UsersDialect = "sqlite"
				nbrew.UsersDB, err = sql.Open(sqliteDriverName, dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "users.json"), dataSourceName, err)
				}
				nbrew.UsersErrorCode = sqliteErrorCode
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
				nbrew.UsersDialect = "postgres"
				nbrew.UsersDB, err = sql.Open("pgx", dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "users.json"), dataSourceName, err)
				}
				nbrew.UsersErrorCode = func(err error) string {
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
				nbrew.UsersDialect = "mysql"
				nbrew.UsersDB = sql.OpenDB(driver)
				nbrew.UsersErrorCode = func(err error) string {
					var mysqlErr *mysql.MySQLError
					if errors.As(err, &mysqlErr) {
						return strconv.FormatUint(uint64(mysqlErr.Number), 10)
					}
					return ""
				}
			default:
				return fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "users.json"), databaseConfig.Dialect)
			}
			err = nbrew.UsersDB.Ping()
			if err != nil {
				return fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "users.json"), nbrew.UsersDialect, dataSourceName, err)
			}
			usersCatalog, err := nb9.UsersCatalog(nbrew.UsersDialect)
			if err != nil {
				return err
			}
			automigrateCmd := &ddl.AutomigrateCmd{
				DB:             nbrew.UsersDB,
				Dialect:        nbrew.UsersDialect,
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
				if nbrew.UsersDialect == "sqlite" {
					nbrew.UsersDB.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
				}
				nbrew.UsersDB.Close()
			}()
		}

		b, err = os.ReadFile(filepath.Join(configDir, "files.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
		}
		b = bytes.TrimSpace(b)
		var filesConfig DatabaseConfig
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
			nbrew.FS = nb9.NewLocalFS(nb9.LocalFSConfig{
				RootDir: filesConfig.Filepath,
				TempDir: os.TempDir(),
			})
		} else {
			var dataSourceName string
			var filesDialect string
			var filesDB *sql.DB
			var filesErrorCode func(error) string
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
				filesDialect = "sqlite"
				filesDB, err = sql.Open(sqliteDriverName, dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
				}
				filesErrorCode = sqliteErrorCode
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
				filesDialect = "postgres"
				filesDB, err = sql.Open("pgx", dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
				}
				filesErrorCode = func(err error) string {
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
				filesDialect = "mysql"
				filesDB = sql.OpenDB(driver)
				filesErrorCode = func(err error) string {
					var mysqlErr *mysql.MySQLError
					if errors.As(err, &mysqlErr) {
						return strconv.FormatUint(uint64(mysqlErr.Number), 10)
					}
					return ""
				}
			default:
				return fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "users.json"), filesConfig.Dialect)
			}
			err = filesDB.Ping()
			if err != nil {
				return fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "users.json"), filesDialect, dataSourceName, err)
			}
			filesCatalog, err := nb9.FilesCatalog(filesDialect)
			if err != nil {
				return err
			}
			automigrateCmd := &ddl.AutomigrateCmd{
				DB:             filesDB,
				Dialect:        filesDialect,
				DestCatalog:    filesCatalog,
				DropObjects:    true, // TODO: turn this off when we go live.
				AcceptWarnings: true,
				Stderr:         io.Discard,
			}
			err = automigrateCmd.Run()
			if err != nil {
				return err
			}
			defer func() {
				if filesDialect == "sqlite" {
					filesDB.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
				}
				filesDB.Close()
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
				storage = nb9.NewFileStorage(objectsDir, os.TempDir())
			}
			nbrew.FS = nb9.NewRemoteFS(nb9.RemoteFSConfig{
				FilesDB:        filesDB,
				FilesDialect:   filesDialect,
				FilesErrorCode: filesErrorCode,
				Storage:        storage,
				UsersDB:        nbrew.UsersDB,
				UsersDialect:   nbrew.UsersDialect,
			})
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
		for _, pair := range [][2]string{
			{"pages/index.html", "embed/index.html"},
			{"output/themes/post.html", "embed/post.html"},
			{"output/themes/postlist.html", "embed/postlist.html"},
		} {
			name, fallback := pair[0], pair[1]
			_, err := fs.Stat(nbrew.FS, name)
			if err == nil {
				continue
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			file, err := nb9.RuntimeFS.Open(fallback)
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter(name, 0644)
			if err != nil {
				return err
			}
			_, err = io.Copy(writer, file)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			err = file.Close()
			if err != nil {
				return err
			}
		}
		// pages/index.html, themes/post.html, themes/postlist.html

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
