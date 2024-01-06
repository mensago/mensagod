package types

// The Result type fills a sorely lacking feature needed for easy error handling
type Result[T any] struct {
	value T
	err   error
}

// Returns true if the Result is not an error
func (r Result[T]) IsOk() bool {
	return r.err == nil
}

// Returns true if the Result contains an error value
func (r Result[T]) IsError() bool {
	return r.err != nil
}

// GetOrValue returns the Result's value or a different value if it contains an error
func (r Result[T]) GetOrValue(v T) T {
	if r.IsOk() {
		return r.value
	}
	return v
}

// Get returns the value of the Result. It will panic if it contains an error
func (r Result[T]) Get() T {
	if r.IsOk() {
		return r.value
	}
	panic(r.err)
}

// Error returns the error in a Result. It will panic if it does not contain an error value.
func (r Result[T]) Error() error {
	if r.IsError() {
		return r.err
	}
	panic("Result.Error() call on non-error value")
}
