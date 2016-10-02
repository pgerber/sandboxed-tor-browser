// config.go - Config file routines.
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

// Package config handles the launcher config file.
package config

import (
	"fmt"
	"os"
	"path"
	"runtime"

	"git.schwanenlied.me/yawning/bulb.git"
	"git.schwanenlied.me/yawning/bulb.git/utils"
	"github.com/BurntSushi/toml"
	xdg "github.com/cep21/xdgbasedir"
)

const (
	appDir     = "sandboxed-tor-browser"
	bundleDir  = "tor-browser"
	configFile = "sandboxed-tor-browser.toml"

	envDisplay       = "DISPLAY"
	envControlPort   = "TOR_CONTROL_PORT"
	envControlPasswd = "TOR_CONTROL_PASSWD"
	envRuntimeDir    = "XDG_RUNTIME_DIR"

	defaultControlPort = "tcp://127.0.0.1:9051"
	defaultChannel     = "release"
	defaultLocale      = "en-US"
	allLocale          = "ALL"

	osLinux     = "linux"
	archLinux32 = "linux32"
	archLinux64 = "linux64"
)

// Unsafe config is the configuration substructure for options that potentially
// reduce security/anonymity.
type Unsafe struct {
	// VolatileExtensionsDir mounts the extensions directory read/write to
	// allow the installation of addons.  The addon auto-update mechanism is
	// still left disabled.
	VolatileExtensionsDir bool

	// EnablePulseAudio enables access to the host PulseAudio daemon inside
	// the sandbox.
	EnablePulseAudio bool
}

// Config is a configuration instance.
type Config struct {
	// ControlPort is the Tor Control Port URI.
	//
	// Valid string representations are:
	//  * tcp://address:port
	//  * unix://path
	//  * port (Translates to tcp://127.0.0.1:port)
	ControlPort string

	// ControlPortPassword is the optional Tor Control Port password.
	ControlPortPassword string

	// Channel is the release channel ("release", "hardened", "alpha").
	Channel string

	// Architecture is the architecture to download ("linux64", "linux32").
	Architecture string

	// Locale is the locale of the bundle to download ("en-US)", "ja-JP").
	Locale string

	// DownloadsDirectory is the path to the host filesystem directory that
	// gets mapped in as `Browser/Downloads`.
	DownloadsDirectory string

	// Display is the X11 DISPLAY env var override.
	Display string

	// Unsafe is the potentially dangerous configuration options.
	Unsafe Unsafe
}

// ControlPortAddr returns the net/addr pair of the Control Port suitable for
// use with Dial.
func (cfg *Config) ControlPortAddr() (net string, addr string, err error) {
	net, addr, err = utils.ParseControlPortString(cfg.ControlPort)
	return
}

// UserDataDir returns the directory where per-user data is to be stored.
func (cfg *Config) UserDataDir() string {
	d, err := xdg.DataHomeDirectory()
	if err != nil {
		panic(err)
	}
	return path.Join(d, appDir)
}

// BundleInstallDir returns the directory where the bundle is installed.
func (cfg *Config) BundleInstallDir() string {
	return path.Join(cfg.UserDataDir(), bundleDir)
}

// RuntimeDir returns the directory where volatile per-user runtime data is to
// be stored.
func (cfg *Config) RuntimeDir() string {
	// The xdg package isn't runtime dir aware.
	d := os.Getenv(envRuntimeDir)
	if d == "" {
		panic(fmt.Errorf("no `%s` set in the enviornment", envRuntimeDir))
	}
	return path.Join(d, appDir)
}

// DialControlPort dials and authenticates to the Tor control port.
func (cfg *Config) DialControlPort() (*bulb.Conn, error) {
	// Connect to the control port, and authenticate.
	net, addr, err := cfg.ControlPortAddr()
	if err != nil {
		return nil, err
	}
	ctrl, err := bulb.Dial(net, addr)
	if err != nil {
		return nil, err
	}
	if err := ctrl.Authenticate(cfg.ControlPortPassword); err != nil {
		ctrl.Close()
		return nil, err
	}
	return ctrl, nil
}

// Load loads and validates the configuration file, returning a ready to use
// Config structure.  Sensible default values will be used if the config file
// is missing.
func Load() (*Config, error) {
	cfg := new(Config)

	// Only load the config file if it actually exists.
	fpath, _ := xdg.GetConfigFileLocation(path.Join(appDir, configFile))
	if _, err := os.Stat(fpath); err == nil {
		// Slurp and parse the config file.
		if _, err = toml.DecodeFile(fpath, cfg); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		// The file not existing is fine, everything else should result in an
		// error.
		return nil, err
	}

	// Apply overrides and default values.
	if cfg.ControlPort == "" {
		if env := os.Getenv(envControlPort); env != "" {
			cfg.ControlPort = env
		} else {
			cfg.ControlPort = defaultControlPort
		}
	}
	if env := os.Getenv(envControlPasswd); env != "" {
		cfg.ControlPortPassword = env
	}
	if cfg.Channel == "" {
		cfg.Channel = defaultChannel
	}
	if cfg.Architecture == "" {
		// The correct value is trivially determined from the runtime.
		if runtime.GOOS != osLinux {
			return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
		}
		switch runtime.GOARCH {
		case "386":
			cfg.Architecture = archLinux32
		case "amd64":
			cfg.Architecture = archLinux64
		default:
			return nil, fmt.Errorf("unsupported Architecture: %s", runtime.GOARCH)
		}
	}
	if cfg.Locale == "" {
		cfg.Locale = defaultLocale
	}
	if cfg.Display == "" {
		cfg.Display = os.Getenv("DISPLAY")
	}

	// Validate.
	if _, _, err := cfg.ControlPortAddr(); err != nil {
		return nil, err
	}
	switch cfg.Channel {
	case "release", "alpha":
	case "hardened":
		cfg.Locale = allLocale
	default:
		return nil, fmt.Errorf("invalid Channel: %v", cfg.Channel)
	}
	switch cfg.Architecture {
	case archLinux32, archLinux64: // Intel Linux only for now.
	default:
		return nil, fmt.Errorf("invalid Architecture: %v", cfg.Architecture)
	}
	if cfg.DownloadsDirectory != "" {
		if fi, err := os.Lstat(cfg.DownloadsDirectory); err != nil {
			return nil, fmt.Errorf("invalid DownloadsDirectory: %v", err)
		} else if !fi.IsDir() {
			return nil, fmt.Errorf("invalid DownloadsDirectory: not a directoru")
		}
	}
	if cfg.Display == "" {
		return nil, fmt.Errorf("invalid or missing DISPLAY")
	}

	return cfg, nil
}
