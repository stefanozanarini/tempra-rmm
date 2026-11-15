//go:build !windows

package executor

import "errors"

func sendSAS() error { return errors.New("Ctrl+Alt+Del is only available on Windows") }
