// ui.go - User interface routines.
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

// Package ui provides common functions and interfaces for the
// sandboxed-tor-browser user interfaces.
package ui

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path"

	"cmd/sandboxed-tor-browser/internal/data"
	"cmd/sandboxed-tor-browser/internal/tor"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

var (
	// BundleChannels is the map of Tor Browser architectures to channels.
	BundleChannels map[string][]string

	// BundleLocales is the map of Tor Browser channels to locales.
	BundleLocales map[string][]string
)

// UI is a user interface implementation.
type UI interface {
	// Run runs the user interface.
	Run() error

	// Cleanup cleans up the user interface prior to termination.
	Term()
}

// Common holds ui implementation agnostic state.
type Common struct {
	Cfg     *config.Config
	Sandbox *exec.Cmd
	tor     *tor.Tor

	lock   *lockFile
	noLock bool

	ForceInstall bool
}

// Init initializes the common interface state.
func (c *Common) Init() error {
	var err error

	// Register the common command line flags.
	flag.BoolVar(&c.noLock, "nolock", false, "Ignore checking the lock file.")
	flag.BoolVar(&c.ForceInstall, "forceInstall", false, "Force (re)installation.")

	// Initialize/load the config file.
	if c.Cfg, err = config.New(); err != nil {
		return err
	}

	// XXX: Validate that the config is somewhat sane.

	return nil
}

// Run handles initiailzing the at-runtime state.
func (c *Common) Run() error {
	// Parse the command line flags.
	flag.Parse()

	// Acquire the lock file.
	if !c.noLock {
		var err error
		if c.lock, err = newLockFile(c); err != nil {
			return err
		}
	}

	return nil
}

// Term handles the common interface state cleanup, prior to termination.
func (c *Common) Term() {
	// Flush the config to disk.
	if c.Cfg != nil {
		c.Cfg.Sync()
	}

	if c.tor != nil {
		c.tor.Shutdown()
		c.tor = nil
	}

	if c.lock != nil {
		c.lock.unlock()
		c.lock = nil
	}
}

type dialFunc func(string, string) (net.Conn, error)

func (c *Common) launchTor(async *Async, onlySystem bool) (dialFunc, error) {
	var err error

	if c.tor != nil {
		log.Printf("launchTor: Shutting down old tor.")
		c.tor.Shutdown()
		c.tor = nil
	}

	if c.Cfg.UseSystemTor {
		// Get the Dial() routine used to reach the external network.
		if c.tor, err = tor.NewSystemTor(c.Cfg.SystemTorControlNet, c.Cfg.SystemTorControlAddr); err != nil {
			async.Err = err
			return nil, err
		}

		// Query the socks port, setup the dialer.
		if dialer, err := c.tor.Dialer(); err != nil {
			async.Err = err
			return nil, err
		} else {
			return dialer.Dial, nil
		}
	} else if !onlySystem {
		// XXX: Launch bundled tor.
		err = fmt.Errorf("launching tor is not supported yet")
		async.Err = err
		return nil, err
	} else if !c.Cfg.NeedsInstall() {
		// That's odd, we only asked for a system tor, but we should be capable
		// of launching tor ourselves.  Don't use a direct connection.
		err = fmt.Errorf("tor bootstrap would be skipped, when we could launch")
		async.Err = err
		return nil, err
	}

	// We must be installing, without a tor daemon already running.
	return net.Dial, nil
}

type lockFile struct {
	f *os.File
}

func (l *lockFile) unlock() {
	defer l.f.Close()
	os.Remove(l.f.Name())
}

func newLockFile(c *Common) (*lockFile, error) {
	const lockFileName = "lock"

	l := new(lockFile)
	p := path.Join(c.Cfg.RuntimeDir, lockFileName)

	var err error
	if l.f, err = os.OpenFile(p, os.O_CREATE|os.O_EXCL, config.FileMode); err != nil {
		return nil, err
	}
	return l, nil
}

func init() {
	BundleChannels = make(map[string][]string)
	if d, err := data.Asset("ui/channels.json"); err != nil {
		panic(err)
	} else if err = json.Unmarshal(d, &BundleChannels); err != nil {
		panic(err)
	}

	BundleLocales = make(map[string][]string)
	if d, err := data.Asset("ui/locales.json"); err != nil {
		panic(err)
	} else if err = json.Unmarshal(d, &BundleLocales); err != nil {
		panic(err)
	}
}
