// config.go - Configuration routines.
// Copyright (C) 2016  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package config handles the launcher configuration.
package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"time"

	"git.schwanenlied.me/yawning/bulb.git/utils"
	xdg "github.com/cep21/xdgbasedir"
)

const (
	// DirMode is the permissions used when making directories.
	DirMode = os.ModeDir | 0700

	// FileMode is the permissions used when making files.
	FileMode = 0600

	configFile = "sandboxed-tor-browser.json"

	defaultChannel = "release"
	defaultLocale  = "en-US"
	archLinux32    = "linux32"
	archLinux64    = "linux64"

	appDir           = "sandboxed-tor-browser"
	bundleInstallDir = "tor-browser"
)

// Config is the sandboxed-tor-browser configuration instance.
type Config struct {
	// Architecture is the current architecture derived at runtime ("linux32",
	// "linux64").
	Architecture string `json:"-"`

	// Channel is the Tor Browser channel to install ("release", "alpha",
	// "hardened").
	Channel string `json:"channel,omitempty"`

	// Locale is the Tor Browser locale to install ("en-US", "ja").
	Locale string `json:"locale,omitempty"`

	// Installed is the installed Tor Browser information.
	Installed *Installed `json:"installed,omitEmpty"`

	// Sandbox is the sandbox configuration.
	Sandbox Sandbox `json:"sandbox,omitEmpty"`

	// FirstLuach is set for the first launch post install.
	FirstLaunch bool `json:"firstLaunch"`

	// UseSystemTor indicates if a system tor daemon should be used.
	UseSystemTor bool `json:"-"`

	// SystemTorControlPort is the system tor daemon control port network.
	SystemTorControlNet string `json:"-"`

	// SystemTorControlAddr is the system tor daemon control port address.
	SystemTorControlAddr string `json:"-"`

	// RumtineDir is `$XDG_RUNTIME_DIR/appDir`.
	RuntimeDir string `json:"-"`

	// UserDataDir is `$XDG_USER_DATA_DIR/appDir`.
	UserDataDir string `json:"-"`

	// BundeInstallDir is `UserDataDir/bundleInstallDir`.
	BundleInstallDir string `json:"-"`

	isDirty bool
	path    string
}

// Installed contains the installed Tor Browser information.
type Installed struct {
	// Version is the installed version.
	Version string `json:"version,omitEmpty"`

	// Architecture is the installed Tor Browser architecture.
	Architecture string `json:"architecture,omitEmpty"`

	// Channel is the installed Tor Browser channel.
	Channel string `json:"channel,omitEmpty"`

	// Locale is the installed Tor Browser locale.
	Locale string `json:"locale,omitEmpty"`

	// LastUpdateCheck is the UNIX time when the last update check was
	// sucessfully completed.
	LastUpdateCheck int64 `json:"lastUpdateCheck,omitEmpty"`
}

// Sandbox contains the sandbox specific config options.
type Sandbox struct {
	cfg *Config

	// Display is the X11 DISPLAY to use in the sandbox.  If omitted, the
	// host system DISPLAY from the env var will be used.
	Display string `json:"display,omitEmpty"`

	// VolatileExtensionsDir mounts the extensions directorey read/write to
	// allow the installation of addons.  The addon auto-update mechanism is
	// still left disabled.
	VolatileExtensionsDir bool `json:"volatileExtensionsDir"`

	// EnablePulseAudio enables access to the host PulseAudio daemon inside the
	// sandbox.
	EnablePulseAudio bool `json:"enablePulseAudio"`

	// DesktopDir is the directory to be bind mounted instead of the default
	// bundle Desktop directory.
	DesktopDir string `json:"desktopDir,omitEmpty"`

	// DownloadsDir is the directory to be bind mounted instead of the default
	// bundle Downloads directory.
	DownloadsDir string `json:"downloadsDir,omitEmpty"`
}

// SetLocale sets the configured locale, and marks the config dirty.
func (cfg *Config) SetLocale(l string) {
	if l != cfg.Locale {
		cfg.isDirty = true
		cfg.Locale = l
	}
}

// SetChannel sets the configured channel, and marks the config dirty.
func (cfg *Config) SetChannel(c string) {
	if c != cfg.Channel {
		cfg.isDirty = true
		cfg.Channel = c
	}
}

// SetInstalled sets the installed Tor Browser, and marks the config dirty.
func (cfg *Config) SetInstalled(i *Installed) {
	cfg.isDirty = true
	cfg.Installed = i
}

// SetInstalledVersion sets the installed version and marks the config dirty.
func (cfg *Config) SetInstalledVersion(v string) {
	cfg.isDirty = true
	cfg.Installed.Version = v
}

// NeedsInstall returns true if the bundle needs to be (re)installed.
func (cfg *Config) NeedsInstall() bool {
	if cfg.Installed == nil {
		return true
	}
	if cfg.Installed.Architecture != cfg.Architecture {
		return true
	}
	if cfg.Installed.Channel != cfg.Channel {
		return true
	}
	if cfg.Installed.Locale != cfg.Locale {
		return true
	}
	return false
}

// SetFirstLaunch sets the first launch flag and marks the config dirty.
func (cfg *Config) SetFirstLaunch(b bool) {
	if cfg.FirstLaunch != b {
		cfg.FirstLaunch = b
		cfg.isDirty = true
	}
}

// SetSandboxEnablePulseAudio sets the sandbox pulse audo enable and marks the
// config dirty.
func (cfg *Config) SetSandboxEnablePulseAudio(b bool) {
	if cfg.Sandbox.EnablePulseAudio != b {
		cfg.Sandbox.EnablePulseAudio = b
		cfg.isDirty = true
	}
}

// SetSandboxVolatileExtensionsDir sets the sandbox extension directory write
// enable and marks the config dirty.
func (cfg *Config) SetSandboxVolatileExtensionsDir(b bool) {
	if cfg.Sandbox.VolatileExtensionsDir != b {
		cfg.Sandbox.VolatileExtensionsDir = b
		cfg.isDirty = true
	}
}

// SetSandboxDownloadsDir sets the sandbox `~/Downloads` bind mount source
// and makrs the config dirty.
func (cfg *Config) SetSandboxDownloadsDir(s string) {
	if cfg.Sandbox.DownloadsDir != s {
		cfg.Sandbox.DownloadsDir = s
		cfg.isDirty = true
	}
}

// SetSandboxDesktopDir sets the sandbox `~/Desktop` bind mount source
// and marks the config dirty.
func (cfg *Config) SetSandboxDesktopDir(s string) {
	if cfg.Sandbox.DesktopDir != s {
		cfg.Sandbox.DesktopDir = s
		cfg.isDirty = true
	}
}

// NeedsUpdateCheck returns true if the bundle needs to be checked for updates,
// and possibly updated.
func (cfg *Config) NeedsUpdateCheck() bool {
	const updateInterval = 60 * 60 * 12 // 12 hours.
	now := time.Now().Unix()
	return (now > cfg.Installed.LastUpdateCheck+updateInterval) || cfg.Installed.LastUpdateCheck > now
}

// SetLastUpdateCheck sets the last update check time and marks the config
// dirty.
func (cfg *Config) SetLastUpdateCheck(t int64) {
	if cfg.Installed.LastUpdateCheck != t {
		cfg.isDirty = true
	}
	cfg.Installed.LastUpdateCheck = t
}

// Sanitize validates the config, and brings it inline with reality.
func (cfg *Config) Sanitize() {
	dirExists := func(d string) bool {
		if d == "" {
			return false
		}
		fi, err := os.Lstat(d)
		if err != nil {
			return false
		}
		return fi.IsDir()
	}
	if !dirExists(cfg.Sandbox.DownloadsDir) {
		cfg.SetSandboxDownloadsDir("")
	}
	if !dirExists(cfg.Sandbox.DesktopDir) {
		cfg.SetSandboxDesktopDir("")
	}
	if !dirExists(cfg.BundleInstallDir) {
		cfg.SetInstalled(nil)
	}
}

// Sync flushes config changes to disk, if the config is dirty.
func (cfg *Config) Sync() error {
	if cfg.isDirty {
		// Encode to JSON and write to disk.
		if b, err := json.Marshal(&cfg); err != nil {
			return err
		} else if err = ioutil.WriteFile(cfg.path, b, FileMode); err != nil {
			return err
		}

		cfg.isDirty = false
	}
	return nil
}

// ResetDirty resets the config's dirty flag, causing changes to be discarded on
// the Sync call.  This routine should only be used immediately prior to
// termination.
func (cfg *Config) ResetDirty() {
	cfg.isDirty = false
}

// New creates a new config object and populates it with the configuration
// from disk if available, default values otherwise.
func New() (*Config, error) {
	const (
		envControlPort = "TOR_CONTROL_PORT"
		envRuntimeDir  = "XDG_RUNTIME_DIR"
	)

	cfg := new(Config)

	// Populate the internal only fields that are not serialized.
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("unsupported OS: %v", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "386":
		cfg.Architecture = archLinux32
	case "amd64":
		cfg.Architecture = archLinux64
	default:
		return nil, fmt.Errorf("unsupported Arch: %v", runtime.GOARCH)
	}
	if env := os.Getenv(envControlPort); env != "" {
		if net, addr, err := utils.ParseControlPortString(env); err != nil {
			return nil, fmt.Errorf("invalid control port: %v", err)
		} else {
			cfg.UseSystemTor = true
			cfg.SystemTorControlNet = net
			cfg.SystemTorControlAddr = addr
		}
	}

	// Initialize the directories that have files in them.  The paths are not
	// serialized but part of the config struct.
	if d := os.Getenv(envRuntimeDir); d == "" {
		return nil, fmt.Errorf("no `%s` set in the enviornment", envRuntimeDir)
	} else {
		cfg.RuntimeDir = path.Join(d, appDir)
	}
	if d, err := xdg.DataHomeDirectory(); err != nil {
		return nil, err
	} else {
		cfg.UserDataDir = path.Join(d, appDir)
		cfg.BundleInstallDir = path.Join(cfg.UserDataDir, bundleInstallDir)
	}
	for _, d := range []string{cfg.RuntimeDir, cfg.UserDataDir} {
		if err := os.MkdirAll(d, DirMode); err != nil {
			return nil, err
		}
	}

	// Ensure the path used to store the config file exits.
	if d, err := xdg.ConfigHomeDirectory(); err != nil {
		return nil, err
	} else {
		d = path.Join(d, appDir)
		if err := os.MkdirAll(d, DirMode); err != nil {
			return nil, err
		}
		cfg.path = path.Join(d, configFile)
	}

	// Load the config file.
	if b, err := ioutil.ReadFile(cfg.path); err != nil {
		// File not found, or failed to read.
		if !os.IsNotExist(err) {
			return nil, err
		}
		cfg.isDirty = true
	} else if err = json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	} else {
		// File exists and was successfully deserialized.
		cfg.isDirty = false
	}

	// Apply sensible defaults for unset items.
	if cfg.Channel == "" {
		cfg.SetChannel(defaultChannel)
	}
	if cfg.Locale == "" {
		cfg.SetLocale(defaultLocale)
	}
	cfg.Sandbox.cfg = cfg

	return cfg, nil
}
