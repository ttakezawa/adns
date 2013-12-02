package main

import (
	"errors"
	"fmt"
	"runtime"
)

type errorWrapper struct {
	err  error
	file string
	line int
}

// Implementation of ``error''.
func (e *errorWrapper) Error() string {
	return fmt.Sprintf("%s at %s:%d", e.err.Error(), e.file, e.line)
}

// Acts as croak of Perl
func newError(msg string) error {
	_, file, line, _ := runtime.Caller(1)
	return &errorWrapper{errors.New(msg), file, line}
}

// Append file name and line number
func wrapError(err error) error {
	_, file, line, _ := runtime.Caller(1)
	return &errorWrapper{err, file, line}
}
