package misc

import "errors"

// ErrBadPath is returned when a bad path is passed to a function
var ErrBadPath = errors.New("invalid path")

var ErrJSONUnmarshal = errors.New("unmarshalling failure")
