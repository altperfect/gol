//go:build !windows

package bof

import "errors"

type Options struct {
	Verbose bool
}

func Execute(_ []byte, _ string, _ []byte) error {
	return ExecuteWithOptions(nil, "", nil, Options{})
}

func ExecuteWithOptions(_ []byte, _ string, _ []byte, _ Options) error {
	return errors.New("BOF execution is only supported on Windows")
}
