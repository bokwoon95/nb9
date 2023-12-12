package sq

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"strings"
)

var (
	errMixedCalls       = fmt.Errorf("rowmapper cannot mix calls to row.Values()/row.Columns()/row.ColumnTypes() with the other row methods")
	errNoFieldsAccessed = fmt.Errorf("rowmapper did not access any fields, unable to determine fields to insert into query")
	errForbiddenCalls   = fmt.Errorf("rowmapper can only contain calls to row.Values()/row.Columns()/row.ColumnTypes() because query's SELECT clause is not dynamic")
)

type Query struct {
	Dialect string
	Format  string
	Values  []any
}

func (query Query) Append(format string, values ...any) Query {
	query.Format += " " + format
	query.Values = append(query.Values, values...)
	return query
}

// A Cursor represents a database cursor.
type Cursor[T any] struct {
	ctx           context.Context
	row           *Row
	rowmapper     func(*Row) T
	logged        int32
	fieldNames    []string
	resultsBuffer *bytes.Buffer
}

// FetchCursor returns a new cursor.
func FetchCursor[T any](ctx context.Context, db DB, query Query, rowmapper func(*Row) T) (cursor *Cursor[T], err error) {
	cursor = &Cursor[T]{
		ctx:       ctx,
		rowmapper: rowmapper,
		row:       &Row{dialect: query.Dialect},
	}

	// Call the rowmapper to populate row.fields and row.scanDest.
	defer func() {
		if r := recover(); r != nil {
			switch r := r.(type) {
			case error:
				if runtimeErr, ok := r.(runtime.Error); ok {
					panic(runtimeErr)
				}
				err = r
			default:
				err = fmt.Errorf(fmt.Sprint(r))
			}
		}
	}()
	cursor.rowmapper(cursor.row)

	format := query.Format
	splitAt := -1
	for i := strings.IndexByte(format, '{'); i >= 0; i = strings.IndexByte(format, '{') {
		if i+2 <= len(format) && format[i:i+2] == "{{" {
			format = format[i+2:]
			continue
		}
		if i+3 <= len(format) && format[i:i+3] == "{*}" {
			splitAt = len(query.Format) - len(format[i:])
			break
		}
		format = format[i+1:]
	}
	if splitAt < 0 {
		return nil, fmt.Errorf("query is missing {*} insertion point")
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	args := argsPool.Get().(*[]any)
	*args = (*args)[:0]
	defer argsPool.Put(args)
	ordinalIndex := ordinalIndexPool.Get().(map[int]int)
	clear(ordinalIndex)
	defer ordinalIndexPool.Put(ordinalIndex)
	runningValuesIndex := 0
	err = writef(ctx, query.Dialect, buf, args, nil, query.Format[:splitAt], query.Values, &runningValuesIndex, ordinalIndex)
	if err != nil {
		return nil, err
	}
	for _, expr := range cursor.row.fetchExprs {
		err = expr.WriteSQL(ctx, query.Dialect, buf, args, nil)
		if err != nil {
			return nil, err
		}
	}
	err = writef(ctx, query.Dialect, buf, args, nil, query.Format[splitAt+3:], query.Values, &runningValuesIndex, ordinalIndex)
	if err != nil {
		return nil, err
	}

	cursor.row.sqlRows, err = db.QueryContext(ctx, buf.String(), *args...)
	if err != nil {
		return nil, err
	}
	return cursor, nil
}

// Next advances the cursor to the next result.
func (cursor *Cursor[T]) Next() bool {
	return cursor.row.sqlRows.Next()
}

// Result returns the cursor result.
func (cursor *Cursor[T]) Result() (result T, err error) {
	cursor.row.index = 0
	defer func() {
		if r := recover(); r != nil {
			switch r := r.(type) {
			case error:
				if runtimeErr, ok := r.(runtime.Error); ok {
					panic(runtimeErr)
				}
				err = r
			default:
				err = fmt.Errorf(fmt.Sprint(r))
			}
		}
	}()
	result = cursor.rowmapper(cursor.row)
	return result, nil
}

// Close closes the cursor.
func (cursor *Cursor[T]) Close() error {
	if err := cursor.row.sqlRows.Close(); err != nil {
		return err
	}
	if err := cursor.row.sqlRows.Err(); err != nil {
		return err
	}
	return nil
}

// FetchOne returns the first result from running the given Query on the given
// DB.
func FetchOne[T any](ctx context.Context, db DB, query Query, rowmapper func(*Row) T) (T, error) {
	cursor, err := FetchCursor(ctx, db, query, rowmapper)
	if err != nil {
		return *new(T), err
	}
	defer cursor.Close()
	if !cursor.Next() {
		return *new(T), sql.ErrNoRows
	}
	result, err := cursor.Result()
	if err != nil {
		return result, err
	}
	return result, cursor.Close()
}

// FetchAll returns all results from running the given Query on the given DB.
func FetchAll[T any](ctx context.Context, db DB, query Query, rowmapper func(*Row) T) ([]T, error) {
	cursor, err := FetchCursor(ctx, db, query, rowmapper)
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []T
	for cursor.Next() {
		result, err := cursor.Result()
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, cursor.Close()
}

// Result is the result of an Exec command.
type Result struct {
	LastInsertId int64
	RowsAffected int64
}

// Exec executes the given Query on the given DB.
func Exec(ctx context.Context, db DB, query Query) (Result, error) {
	var result Result
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	args := argsPool.Get().(*[]any)
	*args = (*args)[:0]
	defer argsPool.Put(args)
	err := Writef(ctx, query.Dialect, buf, args, nil, query.Format, query.Values)
	if err != nil {
		return result, err
	}
	sqlResult, err := db.ExecContext(ctx, buf.String(), *args...)
	if err != nil {
		return result, err
	}
	if query.Dialect == DialectSQLite || query.Dialect == DialectMySQL {
		result.LastInsertId, err = sqlResult.LastInsertId()
		if err != nil {
			return result, err
		}
	}
	result.RowsAffected, err = sqlResult.RowsAffected()
	if err != nil {
		return result, err
	}
	return result, nil
}

type PreparedFetch[T any] struct {
	dialect   string
	args      *[]any
	params    map[string][]int
	rowmapper func(*Row) T
	stmt      *sql.Stmt
}

func PrepareFetch[T any](ctx context.Context, db DB, query Query, rowmapper func(*Row) T) (preparedFetch *PreparedFetch[T], err error) {
	preparedFetch = &PreparedFetch[T]{
		dialect:   query.Dialect,
		args:      argsPool.Get().(*[]any),
		params:    paramsPool.Get().(map[string][]int),
		rowmapper: rowmapper,
	}
	*preparedFetch.args = (*preparedFetch.args)[:0]
	clear(preparedFetch.params)
	row := &Row{dialect: query.Dialect}

	defer func() {
		if r := recover(); r != nil {
			switch r := r.(type) {
			case error:
				if runtimeErr, ok := r.(runtime.Error); ok {
					panic(runtimeErr)
				}
				err = r
			default:
				err = fmt.Errorf(fmt.Sprint(r))
			}
		}
	}()
	rowmapper(row)

	format := query.Format
	splitAt := -1
	for i := strings.IndexByte(format, '{'); i >= 0; i = strings.IndexByte(format, '{') {
		if i+2 <= len(format) && format[i:i+2] == "{{" {
			format = format[i+2:]
			continue
		}
		if i+3 <= len(format) && format[i:i+3] == "{*}" {
			splitAt = len(query.Format) - len(format[i:])
			break
		}
		format = format[i+1:]
	}
	if splitAt < 0 {
		return nil, fmt.Errorf("query is missing {*} insertion point")
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	ordinalIndex := ordinalIndexPool.Get().(map[int]int)
	clear(ordinalIndex)
	defer ordinalIndexPool.Put(ordinalIndex)
	runningValuesIndex := 0
	err = writef(ctx, query.Dialect, buf, preparedFetch.args, preparedFetch.params, query.Format[:splitAt], query.Values, &runningValuesIndex, ordinalIndex)
	if err != nil {
		return nil, err
	}
	for _, expr := range row.fetchExprs {
		err = expr.WriteSQL(ctx, query.Dialect, buf, preparedFetch.args, preparedFetch.params)
		if err != nil {
			return nil, err
		}
	}
	err = writef(ctx, query.Dialect, buf, preparedFetch.args, preparedFetch.params, query.Format[splitAt+3:], query.Values, &runningValuesIndex, ordinalIndex)
	if err != nil {
		return nil, err
	}
	preparedFetch.stmt, err = db.PrepareContext(ctx, buf.String())
	if err != nil {
		return nil, err
	}
	return preparedFetch, nil
}

// Close closes the PreparedFetch.
func (preparedFetch *PreparedFetch[T]) Close() error {
	if preparedFetch.stmt == nil {
		return nil
	}
	defer func() {
		preparedFetch.args = nil
		preparedFetch.params = nil
		preparedFetch.stmt = nil
	}()
	argsPool.Put(preparedFetch.args)
	paramsPool.Put(preparedFetch.params)
	return preparedFetch.stmt.Close()
}

func (preparedFetch *PreparedFetch[T]) FetchCursor(ctx context.Context, params ...Parameter) (cursor *Cursor[T], err error) {
	cursor = &Cursor[T]{
		ctx:       ctx,
		rowmapper: preparedFetch.rowmapper,
		row:       &Row{dialect: preparedFetch.dialect},
	}

	defer func() {
		if r := recover(); r != nil {
			switch r := r.(type) {
			case error:
				if runtimeErr, ok := r.(runtime.Error); ok {
					panic(runtimeErr)
				}
				err = r
			default:
				err = fmt.Errorf(fmt.Sprint(r))
			}
		}
	}()
	cursor.rowmapper(cursor.row)

	// Substitute params.
	newArgs := argsPool.Get().(*[]any)
	*newArgs = (*newArgs)[:0]
	defer argsPool.Put(newArgs)
	err = substituteParams(preparedFetch.dialect, preparedFetch.args, newArgs, preparedFetch.params, params)
	if err != nil {
		return nil, err
	}

	cursor.row.sqlRows, err = preparedFetch.stmt.QueryContext(ctx, *newArgs...)
	if err != nil {
		return nil, err
	}
	return cursor, nil
}

// FetchOne returns the first result from running the PreparedFetch with the
// give params.
func (preparedFetch *PreparedFetch[T]) FetchOne(ctx context.Context, params ...Parameter) (T, error) {
	cursor, err := preparedFetch.FetchCursor(ctx, params...)
	if err != nil {
		return *new(T), err
	}
	defer cursor.Close()
	if !cursor.Next() {
		return *new(T), sql.ErrNoRows
	}
	result, err := cursor.Result()
	if err != nil {
		return result, err
	}
	return result, cursor.Close()
}

// FetchAll returns all the results from running the PreparedFetch with the
// given params.
func (preparedFetch *PreparedFetch[T]) FetchAll(ctx context.Context, params ...Parameter) ([]T, error) {
	cursor, err := preparedFetch.FetchCursor(ctx, params...)
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []T
	for cursor.Next() {
		result, err := cursor.Result()
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, cursor.Close()
}

type PreparedExec struct {
	dialect string
	oldArgs *[]any
	params  map[string][]int
	stmt    *sql.Stmt
}

func PrepareExec(ctx context.Context, db DB, query Query) (*PreparedExec, error) {
	preparedExec := &PreparedExec{
		dialect: query.Dialect,
		oldArgs: argsPool.Get().(*[]any),
		params:  paramsPool.Get().(map[string][]int),
	}
	*preparedExec.oldArgs = (*preparedExec.oldArgs)[:0]
	clear(preparedExec.params)
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	args := argsPool.Get().(*[]any)
	*args = (*args)[:0]
	defer argsPool.Put(args)
	err := Writef(ctx, query.Dialect, buf, args, nil, query.Format, query.Values)
	if err != nil {
		return nil, err
	}
	preparedExec.stmt, err = db.PrepareContext(ctx, buf.String())
	if err != nil {
		return nil, err
	}
	return preparedExec, nil
}

// Exec executes the PreparedExec with the given params.
func (preparedExec *PreparedExec) Exec(ctx context.Context, params ...Parameter) (Result, error) {
	var result Result
	newArgs := argsPool.Get().(*[]any)
	*newArgs = (*newArgs)[:0]
	defer argsPool.Put(newArgs)
	err := substituteParams(preparedExec.dialect, preparedExec.oldArgs, newArgs, preparedExec.params, params)
	if err != nil {
		return result, err
	}
	sqlResult, err := preparedExec.stmt.ExecContext(ctx, *newArgs...)
	if err != nil {
		return result, err
	}
	if preparedExec.dialect == DialectSQLite || preparedExec.dialect == DialectMySQL {
		result.LastInsertId, err = sqlResult.LastInsertId()
		if err != nil {
			return result, err
		}
	}
	result.RowsAffected, err = sqlResult.RowsAffected()
	if err != nil {
		return result, err
	}
	return result, nil
}

// FetchExists returns a boolean indicating if running the given Query on the
// given DB returned any results.
func FetchExists(ctx context.Context, db DB, query Query) (exists bool, err error) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	args := argsPool.Get().(*[]any)
	*args = (*args)[:0]
	defer argsPool.Put(args)
	buf.WriteString("SELECT EXISTS (")
	err = Writef(ctx, query.Dialect, buf, args, nil, query.Format, query.Values)
	if err != nil {
		return false, err
	}
	buf.WriteString(")")
	sqlRows, err := db.QueryContext(ctx, buf.String(), *args...)
	if !sqlRows.Next() {
		return false, sql.ErrNoRows
	}
	err = sqlRows.Scan(&exists)
	if err != nil {
		return false, err
	}
	if err := sqlRows.Close(); err != nil {
		return exists, err
	}
	if err := sqlRows.Err(); err != nil {
		return exists, err
	}
	return exists, nil
}

// substituteParams will return a new args slice by substituting values from
// the given paramValues. The input args slice is untouched.
func substituteParams(dialect string, oldArgs, newArgs *[]any, paramIndexes map[string][]int, params []Parameter) error {
	if cap(*oldArgs) >= len(*newArgs) {
		*oldArgs = (*oldArgs)[:len(*newArgs)]
	} else {
		*oldArgs = make([]any, len(*newArgs))
	}
	copy(*newArgs, *oldArgs)
	var err error
	var value any
	for _, param := range params {
		indexes := paramIndexes[param.Name]
		for _, index := range indexes {
			switch arg := (*newArgs)[index].(type) {
			case sql.NamedArg:
				arg.Value, err = preprocessValue(dialect, param.Value)
				if err != nil {
					return err
				}
				(*newArgs)[index] = arg
			default:
				value, err = preprocessValue(dialect, param.Value)
				if err != nil {
					return err
				}
				(*newArgs)[index] = value
			}
		}
	}
	return nil
}
