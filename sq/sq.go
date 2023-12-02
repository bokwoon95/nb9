package sq

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"reflect"
	"sync"

	"github.com/bokwoon95/nb9/sq/internal/googleuuid"
)

var bufpool = &sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

// Dialects supported.
const (
	DialectSQLite    = "sqlite"
	DialectPostgres  = "postgres"
	DialectMySQL     = "mysql"
	DialectSQLServer = "sqlserver"
)

// SQLWriter is anything that can be converted to SQL.
type SQLWriter interface {
	// WriteSQL writes the SQL representation of the SQLWriter into the query
	// string (*bytes.Buffer) and args slice (*[]any).
	//
	// The params map is used to hold the mappings between named parameters in
	// the query to the corresponding index in the args slice and is used for
	// rebinding args by their parameter name. The params map may be nil, check
	// first before writing to it.
	WriteSQL(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int) error
}

// DB is a database/sql abstraction that can query the database. *sql.Conn,
// *sql.DB and *sql.Tx all implement DB.
type DB interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// Result is the result of an Exec command.
type Result struct {
	LastInsertId int64
	RowsAffected int64
}

// DialectValuer is any type that will yield a different driver.Valuer
// depending on the SQL dialect.
type DialectValuer interface {
	DialectValuer(dialect string) (driver.Valuer, error)
}

// UUIDValue takes in a type whose underlying type must be a [16]byte and
// returns a driver.Valuer.
func UUID(value any) driver.Valuer {
	return &uuidValue{value: value}
}

type uuidValue struct {
	dialect string
	value   any
}

// Value implements the driver.Valuer interface.
func (v *uuidValue) Value() (driver.Value, error) {
	if v.value == nil {
		return nil, nil
	}
	uuid, ok := v.value.([16]byte)
	if !ok {
		value := reflect.ValueOf(v.value)
		typ := value.Type()
		if value.Kind() != reflect.Array || value.Len() != 16 || typ.Elem().Kind() != reflect.Uint8 {
			return nil, fmt.Errorf("%[1]v %[1]T is not [16]byte", v.value)
		}
		for i := 0; i < value.Len(); i++ {
			uuid[i] = value.Index(i).Interface().(byte)
		}
	}
	if v.dialect != DialectPostgres {
		return uuid[:], nil
	}
	var buf [36]byte
	googleuuid.EncodeHex(buf[:], uuid)
	return string(buf[:]), nil
}

// DialectValuer implements the DialectValuer interface.
func (v *uuidValue) DialectValuer(dialect string) (driver.Valuer, error) {
	v.dialect = dialect
	return v, nil
}
