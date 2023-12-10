package sq

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"time"

	"github.com/bokwoon95/nb9/sq/internal/googleuuid"
)

// Row represents the state of a row after a call to rows.Next().
type Row struct {
	dialect    string
	sqlRows    *sql.Rows
	index      int
	fetchExprs []Expression
	scanDest   []any
}

// Scan scans the expression into destPtr.
func (row *Row) Scan(destPtr any, format string, values ...any) {
	if row.sqlRows == nil {
		row.fetchExprs = append(row.fetchExprs, Expression{Format: format, Values: values})
		switch destPtr.(type) {
		case *bool, *sql.NullBool:
			row.scanDest = append(row.scanDest, &sql.NullBool{})
		case *float64, *sql.NullFloat64:
			row.scanDest = append(row.scanDest, &sql.NullFloat64{})
		case *int32, *sql.NullInt32:
			row.scanDest = append(row.scanDest, &sql.NullInt32{})
		case *int, *int64, *sql.NullInt64:
			row.scanDest = append(row.scanDest, &sql.NullInt64{})
		case *string, *sql.NullString:
			row.scanDest = append(row.scanDest, &sql.NullString{})
		case *time.Time, *sql.NullTime:
			row.scanDest = append(row.scanDest, &sql.NullTime{})
		default:
			if reflect.TypeOf(destPtr).Kind() != reflect.Ptr {
				panic(fmt.Errorf(callsite(1)+"cannot pass in non pointer value (%#v) as destPtr", destPtr))
			}
			row.scanDest = append(row.scanDest, destPtr)
		}
		return
	}
	defer func() {
		row.index++
	}()
	switch destPtr := destPtr.(type) {
	case *bool:
		scanDest := row.scanDest[row.index].(*sql.NullBool)
		*destPtr = scanDest.Bool
	case *sql.NullBool:
		scanDest := row.scanDest[row.index].(*sql.NullBool)
		*destPtr = *scanDest
	case *float64:
		scanDest := row.scanDest[row.index].(*sql.NullFloat64)
		*destPtr = scanDest.Float64
	case *sql.NullFloat64:
		scanDest := row.scanDest[row.index].(*sql.NullFloat64)
		*destPtr = *scanDest
	case *int:
		scanDest := row.scanDest[row.index].(*sql.NullInt64)
		*destPtr = int(scanDest.Int64)
	case *int32:
		scanDest := row.scanDest[row.index].(*sql.NullInt32)
		*destPtr = scanDest.Int32
	case *sql.NullInt32:
		scanDest := row.scanDest[row.index].(*sql.NullInt32)
		*destPtr = *scanDest
	case *int64:
		scanDest := row.scanDest[row.index].(*sql.NullInt64)
		*destPtr = scanDest.Int64
	case *sql.NullInt64:
		scanDest := row.scanDest[row.index].(*sql.NullInt64)
		*destPtr = *scanDest
	case *string:
		scanDest := row.scanDest[row.index].(*sql.NullString)
		*destPtr = scanDest.String
	case *sql.NullString:
		scanDest := row.scanDest[row.index].(*sql.NullString)
		*destPtr = *scanDest
	case *time.Time:
		scanDest := row.scanDest[row.index].(*sql.NullTime)
		*destPtr = scanDest.Time
	case *sql.NullTime:
		scanDest := row.scanDest[row.index].(*sql.NullTime)
		*destPtr = *scanDest
	default:
		destValue := reflect.ValueOf(destPtr).Elem()
		srcValue := reflect.ValueOf(row.scanDest[row.index]).Elem()
		destValue.Set(srcValue)
	}
}

// Bytes returns the []byte value of the expression.
func (row *Row) Bytes(format string, values ...any) []byte {
	if row.sqlRows == nil {
		row.fetchExprs = append(row.fetchExprs, Expression{Format: format, Values: values})
		row.scanDest = append(row.scanDest, &nullBytes{dialect: row.dialect})
		return nil
	}
	defer func() {
		row.index++
	}()
	scanDest := row.scanDest[row.index].(*nullBytes)
	var b []byte
	if scanDest.valid {
		b = make([]byte, len(scanDest.bytes))
		copy(b, scanDest.bytes)
	}
	return b
}

// Bool returns the bool value of the expression.
func (row *Row) Bool(format string, values ...any) bool {
	return row.NullBool(format, values...).Bool
}

// NullBool returns the sql.NullBool value of the expression.
func (row *Row) NullBool(format string, values ...any) sql.NullBool {
	if row.sqlRows == nil {
		row.fetchExprs = append(row.fetchExprs, Expression{Format: format, Values: values})
		row.scanDest = append(row.scanDest, &sql.NullBool{})
		return sql.NullBool{}
	}
	defer func() {
		row.index++
	}()
	scanDest := row.scanDest[row.index].(*sql.NullBool)
	return *scanDest
}

// Float64 returns the float64 value of the expression.
func (row *Row) Float64(format string, values ...any) float64 {
	return row.NullFloat64(format, values...).Float64
}

// NullFloat64 returns the sql.NullFloat64 valye of the expression.
func (row *Row) NullFloat64(format string, values ...any) sql.NullFloat64 {
	if row.sqlRows == nil {
		row.fetchExprs = append(row.fetchExprs, Expression{Format: format, Values: values})
		row.scanDest = append(row.scanDest, &sql.NullFloat64{})
		return sql.NullFloat64{}
	}
	defer func() {
		row.index++
	}()
	scanDest := row.scanDest[row.index].(*sql.NullFloat64)
	return *scanDest
}

// Int returns the int value of the expression.
func (row *Row) Int(format string, values ...any) int {
	return int(row.NullInt64(format, values...).Int64)
}

// Int64 returns the int64 value of the expression.
func (row *Row) Int64(format string, values ...any) int64 {
	return row.NullInt64(format, values...).Int64
}

// NullInt64 returns the sql.NullInt64 value of the expression.
func (row *Row) NullInt64(format string, values ...any) sql.NullInt64 {
	if row.sqlRows == nil {
		row.fetchExprs = append(row.fetchExprs, Expression{Format: format, Values: values})
		row.scanDest = append(row.scanDest, &sql.NullInt64{})
		return sql.NullInt64{}
	}
	defer func() {
		row.index++
	}()
	scanDest := row.scanDest[row.index].(*sql.NullInt64)
	return *scanDest
}

// String returns the string value of the expression.
func (row *Row) String(format string, values ...any) string {
	return row.NullString(format, values...).String
}

// NullString returns the sql.NullString value of the expression.
func (row *Row) NullString(format string, values ...any) sql.NullString {
	if row.sqlRows == nil {
		row.fetchExprs = append(row.fetchExprs, Expression{Format: format, Values: values})
		row.scanDest = append(row.scanDest, &sql.NullString{})
		return sql.NullString{}
	}
	defer func() {
		row.index++
	}()
	scanDest := row.scanDest[row.index].(*sql.NullString)
	return *scanDest
}

// Time returns the time.Time value of the expression.
func (row *Row) Time(format string, values ...any) time.Time {
	return row.NullTime(format, values...).Time
}

// NullTime returns the sql.NullTime value of the expression.
func (row *Row) NullTime(format string, values ...any) sql.NullTime {
	if row.sqlRows == nil {
		row.fetchExprs = append(row.fetchExprs, Expression{Format: format, Values: values})
		row.scanDest = append(row.scanDest, &sql.NullTime{})
		return sql.NullTime{}
	}
	defer func() {
		row.index++
	}()
	scanDest := row.scanDest[row.index].(*sql.NullTime)
	return *scanDest
}

// UUID scans the UUID expression into destPtr.
func (row *Row) UUID(destPtr any, format string, values ...any) {
	if row.sqlRows == nil {
		if _, ok := destPtr.(*[16]byte); !ok {
			if reflect.TypeOf(destPtr).Kind() != reflect.Ptr {
				panic(fmt.Errorf(callsite(1)+"cannot pass in non pointer value (%#v) as destPtr", destPtr))
			}
			destValue := reflect.ValueOf(destPtr).Elem()
			if destValue.Kind() != reflect.Array || destValue.Len() != 16 || destValue.Type().Elem().Kind() != reflect.Uint8 {
				panic(fmt.Errorf(callsite(1)+"%T is not a pointer to a [16]byte", destPtr))
			}
		}
		row.fetchExprs = append(row.fetchExprs, Expression{Format: format, Values: values})
		row.scanDest = append(row.scanDest, &nullBytes{dialect: row.dialect, displayType: displayTypeUUID})
		return
	}
	defer func() {
		row.index++
	}()
	scanDest := row.scanDest[row.index].(*nullBytes)
	var err error
	var uuid [16]byte
	if len(scanDest.bytes) == 16 {
		copy(uuid[:], scanDest.bytes)
	} else {
		uuid, err = googleuuid.ParseBytes(scanDest.bytes)
		if err != nil {
			panic(fmt.Errorf(callsite(1)+"parsing %q as UUID string: %w", string(scanDest.bytes), err))
		}
	}
	if destArrayPtr, ok := destPtr.(*[16]byte); ok {
		copy((*destArrayPtr)[:], uuid[:])
		return
	}
	destValue := reflect.ValueOf(destPtr).Elem()
	for i := 0; i < 16; i++ {
		destValue.Index(i).Set(reflect.ValueOf(uuid[i]))
	}
}

func callsite(skip int) string {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return ""
	}
	return filepath.Base(file) + ":" + strconv.Itoa(line) + ": "
}

type displayType int8

const (
	displayTypeBinary displayType = iota
	displayTypeString
	displayTypeUUID
)

// nullBytes is used in place of scanning into *[]byte. We use *nullBytes
// instead of *[]byte because of the displayType field, which determines how to
// render the value to the user. This is important for logging the query
// results, because UUIDs/JSON/Arrays are all scanned into bytes but we don't
// want to display them as bytes (we need to convert them to UUID/JSON/Array
// strings instead).
type nullBytes struct {
	bytes       []byte
	dialect     string
	displayType displayType
	valid       bool
}

func (n *nullBytes) Scan(value any) error {
	if value == nil {
		n.bytes, n.valid = nil, false
		return nil
	}
	n.valid = true
	switch value := value.(type) {
	case string:
		n.bytes = []byte(value)
	case []byte:
		n.bytes = value
	default:
		return fmt.Errorf("unable to convert %#v to bytes", value)
	}
	return nil
}

func (n *nullBytes) Value() (driver.Value, error) {
	if !n.valid {
		return nil, nil
	}
	switch n.displayType {
	case displayTypeString:
		return string(n.bytes), nil
	case displayTypeUUID:
		if n.dialect != "postgres" {
			return n.bytes, nil
		}
		var uuid [16]byte
		var buf [36]byte
		copy(uuid[:], n.bytes)
		googleuuid.EncodeHex(buf[:], uuid)
		return string(buf[:]), nil
	default:
		return n.bytes, nil
	}
}
