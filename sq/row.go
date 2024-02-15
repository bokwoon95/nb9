package sq

import (
	"database/sql"
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
		if reflect.TypeOf(destPtr).Kind() != reflect.Ptr {
			panic(fmt.Errorf(callsite(1)+"cannot pass in non pointer value (%#v) as destPtr", destPtr))
		}
		row.fetchExprs = append(row.fetchExprs, Expression{Format: format, Values: values})
		row.scanDest = append(row.scanDest, destPtr)
		return
	}
	defer func() {
		row.index++
	}()
	destValue := reflect.ValueOf(destPtr).Elem()
	srcValue := reflect.ValueOf(row.scanDest[row.index]).Elem()
	destValue.Set(srcValue)
}

// Bytes returns the []byte value of the expression.
func (row *Row) Bytes(b []byte, format string, values ...any) []byte {
	if row.sqlRows == nil {
		row.fetchExprs = append(row.fetchExprs, Expression{Format: format, Values: values})
		row.scanDest = append(row.scanDest, &sql.RawBytes{})
		return nil
	}
	defer func() {
		row.index++
	}()
	scanDest := row.scanDest[row.index].(*sql.RawBytes)
	if scanDest == nil {
		return nil
	}
	if cap(b) < len(*scanDest) {
		b = make([]byte, len(*scanDest))
	}
	b = b[:len(*scanDest)]
	copy(b, *scanDest)
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
		row.scanDest = append(row.scanDest, &Timestamp{})
		return sql.NullTime{}
	}
	defer func() {
		row.index++
	}()
	scanDest := row.scanDest[row.index].(*Timestamp)
	return sql.NullTime{
		Time:  scanDest.Time,
		Valid: scanDest.Valid,
	}
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
		row.scanDest = append(row.scanDest, &sql.RawBytes{})
		return
	}
	defer func() {
		row.index++
	}()
	var err error
	var uuid [16]byte
	scanDest := row.scanDest[row.index].(*sql.RawBytes)
	if *scanDest != nil {
		if len(*scanDest) == 16 {
			copy(uuid[:], *scanDest)
		} else {
			uuid, err = googleuuid.ParseBytes(*scanDest)
			if err != nil {
				panic(fmt.Errorf(callsite(1)+"parsing %q as UUID string: %w", string(*scanDest), err))
			}
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
