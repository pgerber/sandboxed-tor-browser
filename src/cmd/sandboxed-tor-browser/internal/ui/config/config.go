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

	"git.schwanenlied.me/yawning/bulb.git/utils"
	xdg "github.com/cep21/xdgbasedir"
)

const (
	// AppDir is the subdirectory under which sandboxed-tor-browser files are
	// kept, relative to the various XDG directories.
	AppDir = "sandboxed-tor-browser"

	// DirMode is the permissions used when making directories.
	DirMode = os.ModeDir | 0700

	// FileMode is the permissions used when making files.
	FileMode = 0600

	configFile = "sandboxed-tor-browser.json"

	defaultChannel = "release"
	defaultLocale  = "en-US"

	archLinux32 = "linux32"
	archLinux64 = "linux64"
)

// Config is the sandboxed-tor-browser configuration instance.
type Config struct {
	// Architecture is the current architecture derived at runtime.
	Architecture string `json:"-"`

	// Channel is the Tor Browser channel to install.
	Channel string `json:"channel,omitempty"`

	// Locale is the Tor Browser locale to install.
	Locale string `json:"locale,omitempty"`

	// Installed is the installed Tor Browser information.
	Installed *Installed `json:"installed,omitEmpty"`

	// UseSystemTor indicates if a system tor daemon should be used.
	UseSystemTor bool `json:"-"`

	// SystemTorControlPort is the system tor daemon control port network.
	SystemTorControlNet string `json:"-"`

	// SystemTorControlAddr is the system tor daemon control port address.
	SystemTorControlAddr string `json:"-"`

	isDirty bool
	path    string
}

type Installed struct {
	// Version is the installed version.
	Version string `json:"version,omitEmpty"`

	// Architecture is the installed Tor Browser architecture.
	Architecture string `json:"architecture,omitEmpty"`

	// Channel is the installed Tor Browser channel.
	Channel string `json:"channel,omitEmpty"`

	// Locale is the installed Tor Browser locale.
	Locale string `json:"locale,omitEmpty"`
}

// SetLocale sets the configured locale, and marks the config dirty.
func (cfg *Config) SetLocale(l string) {
	if l != cfg.Locale {
		cfg.isDirty = true
	}
	cfg.Locale = l
}

// SetChannel sets the configured channel, and marks the config dirty.
func (cfg *Config) SetChannel(c string) {
	if c != cfg.Channel {
		cfg.isDirty = true
	}
	cfg.Channel = c
}

// SetInstalled sets the installed Tor Browser, and marks the config dirty.
func (cfg *Config) SetInstalled(i *Installed) {
	cfg.isDirty = true
	cfg.Installed = i
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

// NewConfig creates a new config object and populates it with the
// configuration from disk if available, default values otherwise.
func New() (*Config, error) {
	const envControlPort = "TOR_CONTROL_PORT"

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

	// Ensure the path used to store the config file exits.
	if d, err := xdg.ConfigHomeDirectory(); err != nil {
		return nil, err
	} else {
		d = path.Join(d, AppDir)
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

	return cfg, nil
}