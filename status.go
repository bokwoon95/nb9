package nb9

import (
	"strings"
)

type Status string

const (
	Success       = Status("Success")
	UpdateSuccess = Status("UpdateSuccess")

	// TODO: do we really have to make it an error? What scenarios will we have
	// to treat status strings as errors? If not, remove the error interface
	// from the Status type entirely.
	ErrBadRequest           = Status("BadRequest")
	ErrNotAuthenticated     = Status("NotAuthenticated")
	ErrNotAuthorized        = Status("NotAuthorized")
	ErrNotFound             = Status("NotFound")
	ErrMethodNotAllowed     = Status("MethodNotAllowed")
	ErrUnsupportedMediaType = Status("UnsupportedMediaType")
	ErrServerError          = Status("ServerError")
)

func (s Status) Error() string {
	return string(s)
}

func (s Status) Code() string {
	n := strings.Index(string(s), ":")
	if n < 0 {
		return string(s)
	}
	return string(s[:n])
}

func (s Status) Equal(target Status) bool {
	return s.Code() == target.Code()
}

func (s Status) Is(target error) bool {
	if target, ok := target.(Status); ok {
		return s.Equal(target)
	}
	return false
}
