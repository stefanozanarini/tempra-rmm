//go:build windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	installKey = `SOFTWARE\TempraRMM`
	policyKey  = `SOFTWARE\Policies\TempraRMM`
	// legacy{Install,Policy}Key are where versions before the TempraRMM
	// rebrand kept these values. Still read, at lower precedence, so an
	// already-enrolled agent keeps working immediately after it updates,
	// before a GPO or a fresh MSI run has caught up to the new key.
	legacyInstallKey = `SOFTWARE\open-rmm`
	legacyPolicyKey  = `SOFTWARE\Policies\open-rmm`
)

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

// DefaultConfigPath is where the agent looks for its configuration.
func DefaultConfigPath() string { return filepath.Join(programData(), "TempraRMM", "agent.json") }

// DefaultDataDir is where the agent keeps keys and state.
func DefaultDataDir() string { return filepath.Join(programData(), "TempraRMM", "data") }

// DefaultInstallDir holds the installed versions.
func DefaultInstallDir() string {
	if p := os.Getenv("ProgramFiles"); p != "" {
		return filepath.Join(p, "TempraRMM")
	}
	return `C:\Program Files\TempraRMM`
}

// migrateOS moves an already-enrolled agent's configuration file and data
// directory (keys, certificate, state) from the pre-rebrand ProgramData\
// open-rmm to ProgramData\TempraRMM, the first time a renamed build runs on
// a machine that still has the old layout. A rename is atomic and, since
// both folders are on the same ProgramData volume, effectively instant.
//
// A service already running keeps the -config path its Windows service
// entry was last set to; a self-update (the normal path in the field, as
// opposed to a fresh MSI run) never rewrites that argument, so it is
// typically still the pre-rebrand default path itself. When path is exactly
// that legacy file, it is the one just moved: return the new path so the
// caller reads the migrated file instead of one that no longer exists.
func migrateOS(path string) string {
	old := filepath.Join(programData(), "open-rmm")
	legacyConfigPath := filepath.Join(old, "agent.json")
	moveIfMissing(legacyConfigPath, DefaultConfigPath())
	moveIfMissing(filepath.Join(old, "data"), DefaultDataDir())
	// Windows paths are case-insensitive; the -config argument on an
	// existing service was written by code that may have cased it
	// differently (e.g. a lowercase drive letter).
	if strings.EqualFold(filepath.Clean(path), filepath.Clean(legacyConfigPath)) {
		return DefaultConfigPath()
	}
	return path
}

// moveIfMissing renames old to dst when dst does not exist yet and old
// does; the MSI pre-creates an empty TempraRMM ProgramData folder, so dst's
// parent may already exist even when dst itself has never been written.
func moveIfMissing(old, dst string) {
	if _, err := os.Stat(dst); err == nil {
		return
	}
	if _, err := os.Stat(old); err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(dst), 0o700)
	_ = os.Rename(old, dst)
}

// ForgetEnrollToken deletes the token written by the MSI once the agent is
// enrolled, so it does not linger in the registry (both the current key and,
// on a machine enrolled before the TempraRMM rebrand, the legacy one). A
// token set by GPO (Policies key) is managed by the domain and left alone.
func ForgetEnrollToken() error {
	var last error
	for _, path := range []string{installKey, legacyInstallKey} {
		if err := forgetEnrollTokenAt(path); err != nil {
			last = err
		}
	}
	return last
}

func forgetEnrollTokenAt(path string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	err = k.DeleteValue("EnrollToken")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}

// overlayOS applies the MSI key, then the GPO policy key on top of it.
//
// Registry values (all optional):
//
//	Server            REG_SZ        agent.example.com:443
//	RootCA            REG_SZ        PEM of the root certificate
//	EnrollToken       REG_SZ        enrollment token
//	RootCA can also be base64 DER (single line)
//	JobSigningKeys    REG_MULTI_SZ, or REG_SZ separated by , or ;
//	ModuleSigningKeys  idem
//	ReleaseSigningKeys idem
//	AllowAdHocScripts REG_DWORD 0/1, or REG_SZ "0"/"1" (empty: not set)
//	AllowInteractiveShell REG_DWORD 0/1 (default 1; the MSI writes 1)
//	AllowRemoteControl REG_DWORD 0/1 (default 1; the MSI writes 1)
//	MaxConcurrentJobs REG_DWORD     1-32
func overlayOS(c *Config) error {
	for _, path := range []string{legacyInstallKey, legacyPolicyKey, installKey, policyKey} {
		if err := overlayKey(c, path); err != nil {
			return err
		}
	}
	return nil
}

// keys reads a list of public keys, as REG_MULTI_SZ or as a REG_SZ with
// comma or semicolon separators (what MSI properties and ADMX text produce).
func keys(k registry.Key, name string, dst *[]string) {
	if v, _, err := k.GetStringsValue(name); err == nil && len(v) > 0 {
		*dst = v
		return
	}
	if v, _, err := k.GetStringValue(name); err == nil {
		if l := SplitList(v); len(l) > 0 {
			*dst = l
		}
	}
}

func overlayKey(c *Config, path string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	str := func(name string, dst *string) {
		if v, _, err := k.GetStringValue(name); err == nil && strings.TrimSpace(v) != "" {
			*dst = strings.TrimSpace(v)
		}
	}
	str("Server", &c.Server)
	str("EnrollToken", &c.EnrollToken)
	if v, _, err := k.GetStringValue("RootCA"); err == nil && strings.TrimSpace(v) != "" {
		c.RootCAPEM = v
		c.RootCAFile = ""
	}
	keys(k, "JobSigningKeys", &c.JobSigningKeys)
	keys(k, "ModuleSigningKeys", &c.ModuleSigningKeys)
	keys(k, "ReleaseSigningKeys", &c.ReleaseSigningKeys)
	if v, _, err := k.GetIntegerValue("MaxConcurrentJobs"); err == nil && v <= 32 {
		c.MaxConcurrentJobs = int(v)
	}
	if v, _, err := k.GetIntegerValue("AllowInteractiveShell"); err == nil {
		b := v != 0
		c.AllowInteractiveShell = &b
	}
	if v, _, err := k.GetIntegerValue("AllowRemoteControl"); err == nil {
		b := v != 0
		c.AllowRemoteControl = &b
	}
	// DWORD (ADMX, manual) or string "0"/"1" (MSI); empty means "not set".
	if v, _, err := k.GetIntegerValue("AllowAdHocScripts"); err == nil {
		b := v != 0
		c.AllowAdHocScripts = &b
	} else if v, _, err := k.GetStringValue("AllowAdHocScripts"); err == nil {
		switch strings.TrimSpace(v) {
		case "0":
			b := false
			c.AllowAdHocScripts = &b
		case "1":
			b := true
			c.AllowAdHocScripts = &b
		}
	}
	return nil
}
