package misc

import "errors"

var ErrBadPath = errors.New("invalid path")

var ErrJSONUnmarshal = errors.New("unmarshalling failure")

var ErrInvalidAddress = errors.New("invalid address")
var ErrInvalidDomain = errors.New("invalid domain")
var ErrInvalidID = errors.New("invalid id")

var ErrExpired = errors.New("expired")
var ErrLimitReached = errors.New("limit reached")
var ErrOutOfRange = errors.New("out of range")

var ErrNotFound = errors.New("not found")
var ErrExists = errors.New("exists")
var ErrMismatch = errors.New("mismatch")
var ErrCanceled = errors.New("canceled")
var ErrMissingArgument = errors.New("missing argument")
var ErrBadArgument = errors.New("bad argument")

var ErrTimedOut = errors.New("timed out")

var ErrUnimplemented = errors.New("unimplemented")
