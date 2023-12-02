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
// - NOTE: a prime use would be to identify queries that take like, up big
// seconds. We only have 60 seconds per request, and we are interested in the
// heaviest SQL queries (the ones that take the longest time). However, we
// don't know the cutoff because it's very likely all our queries end up below
// the cutoff or above the cutoff. What we need is some kind of statistical
// analysis as each data point comes in to determine the min, max, median
// latencies and so forth.
// - NOTE: BUT: It may be more important to log the overall latencies instead
// of just the query latencies. We can ignore logging the queries first. Only
// when we've proven that there is a latency problem with some HTTP requests
// (if they're timing out of the 60 second deadline) then we can dig deeper
// into which parts of the requests are taking the most time (and we caan
// modify it entirely within notebrew since it's a homegrown query builder).
// WithAttrs(slog.String("query", "SELECT * FROM ..."), slog.String("args", "1:'' 2:3 3:'' 5:''"))
// Q1: do we wrap the DB with a logger like in old sq?
// Q2: always interpolate? don't interpolate? interpolate only if no error? huh?
