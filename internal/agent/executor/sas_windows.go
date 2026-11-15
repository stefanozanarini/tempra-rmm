//go:build windows

package executor

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var procSendSAS = windows.NewLazySystemDLL("sas.dll").NewProc("SendSAS")

const (
	sasPolicyKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	sasPolicyValue = "SoftwareSASGeneration"
)

// sendSAS presses Ctrl+Alt+Del on the console session. Windows lets only
// a service (or an accessibility tool) generate it, and only if the
// SoftwareSASGeneration policy allows services (1 or 3): left unset it is
// set to 1, services only; a value set to forbid it (Group Policy) is
// respected and reported.
func sendSAS() error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, sasPolicyKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open the SAS policy: %w", err)
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(sasPolicyValue)
	switch {
	case errors.Is(err, registry.ErrNotExist):
		if err := k.SetDWordValue(sasPolicyValue, 1); err != nil {
			return fmt.Errorf("allow services to send Ctrl+Alt+Del: %w", err)
		}
	case err != nil:
		return fmt.Errorf("read the SAS policy: %w", err)
	case v != 1 && v != 3:
		return fmt.Errorf("Ctrl+Alt+Del is not allowed by the policy %s=%d (1 or 3 lets services send it)", sasPolicyValue, v)
	}
	if err := procSendSAS.Find(); err != nil {
		return err
	}
	_, _, _ = procSendSAS.Call(0) // FALSE: the caller is a service; SendSAS returns nothing
	return nil
}
