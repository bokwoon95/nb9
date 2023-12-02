package sq

import (
	"bytes"
	"context"
	"fmt"
)

var (
	errMixedCalls       = fmt.Errorf("rowmapper cannot mix calls to row.Values()/row.Columns()/row.ColumnTypes() with the other row methods")
	errNoFieldsAccessed = fmt.Errorf("rowmapper did not access any fields, unable to determine fields to insert into query")
	errForbiddenCalls   = fmt.Errorf("rowmapper can only contain calls to row.Values()/row.Columns()/row.ColumnTypes() because query's SELECT clause is not dynamic")
)

// A Cursor represents a database cursor.
type Cursor[T any] struct {
	ctx           context.Context
	row           *Row
	rowmapper     func(*Row) T
	logged        int32
	fieldNames    []string
	resultsBuffer *bytes.Buffer
}

// TODO: kind of logging does notebrew need to do? Performantly?
// only in dev? when we toggle a switch, how do we log stuff efficiently to the console?
// - What goals exactly are we looking for when we log queries?
// - For new developers to see how the sausage is made?
// - To identify problematic queries?
// - To surface errors in queries? Will the end-user (desktop users) ever see the errors logged to console?
// WithAttrs(slog.String("query", "SELECT * FROM ..."), slog.String("args", "1:'' 2:3 3:'' 5:''"))
// Q1: do we wrap the DB with a logger like in old sq?
// Q2: always interpolate? don't interpolate? interpolate only if no error? huh?
