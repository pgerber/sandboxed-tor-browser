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
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"git.schwanenlied.me/yawning/grab.git"
	xdg "github.com/cep21/xdgbasedir"

	"cmd/sandboxed-tor-browser/internal/data"
	"cmd/sandboxed-tor-browser/internal/installer"
	"cmd/sandboxed-tor-browser/internal/tor"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

var (
	// BundleChannels is the map of Tor Browser architectures to channels.
	BundleChannels map[string][]string

	// BundleLocals is the map of Tor Browser channels to lcoales.
	BundleLocales map[string][]string
)

// ErrCanceled is the error set when an async operation was canceled.
var ErrCanceled = errors.New("async operation canceled")

// Async is the structure containing the bits needed to communicate from
// a long running async task back to the UI (eg: Installation).
type Async struct {
	sync.Mutex

	// Cancel is used to signal cancelation to the task.
	Cancel chan interface{}

	// Done is used to signal completion to the UI.
	Done chan interface{}

	// Err is the final completion status.
	Err error

	// UpdateProgress is the function called to give progress feedback to
	// the UI.
	UpdateProgress func(string)
}

func (async *Async) grab(client *grab.Client, url string, hzFn func(string)) []byte {
	if req, err := grab.NewRequest(url); err != nil {
		async.Err = err
		return nil
	} else {
		req.Buffer = &bytes.Buffer{}
		var resp *grab.Response

		ch := client.DoAsync(req)
		select {
		case resp = <-ch:
		case <-async.Cancel:
			client.CancelRequest(req)
			async.Err = ErrCanceled
			return nil
		}

		// Wait for the transfer to complete.
		t := time.NewTicker(1000 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-async.Cancel:
				client.CancelRequest(req)
				async.Err = ErrCanceled
				return nil
			case <-t.C:
				if resp.IsComplete() {
					if resp.Error != nil {
						async.Err = resp.Error
						return nil
					}
					return req.Buffer.Bytes()
				} else if hzFn != nil {
					remaining := resp.ETA().Sub(time.Now()).Seconds()
					hzFn(fmt.Sprintf("%vs remaining", int(remaining)))
				}
				runtime.Gosched()
			}
		}
	}
}

// NewAsync creates a new Async structure.
func NewAsync() *Async {
	async := new(Async)
	async.Cancel = make(chan interface{})
	async.Done = make(chan interface{})
	return async
}

// UI is a user interface implementation.
type UI interface {
	// Run runs the user interface.
	Run() error

	// Cleanup cleans up the user interface prior to termination.
	Term()
}

// Common holds ui implementation agnostic state.
type Common struct {
	Cfg *config.Config

	RuntimeDir       string
	UserDataDir      string
	BundleInstallDir string

	lock   *lockFile
	noLock bool

	tor *tor.Tor
}

// Init initializes the common interface state.
func (c *Common) Init() error {
	const (
		envRuntimeDir    = "XDG_RUNTIME_DIR"
		bundleInstallDir = "tor-browser-2" // XXX: Change this.
	)

	// Register the common command line flags.
	flag.BoolVar(&c.noLock, "nolock", false, "Ignore checking the lock file.")

	// Initialize XDG_RUNTIME_DIR.
	d := os.Getenv(envRuntimeDir)
	if d == "" {
		return fmt.Errorf("no `%s` set in the enviornment", envRuntimeDir)
	}
	c.RuntimeDir = path.Join(d, config.AppDir)

	// Initialize the data directory.
	d, err := xdg.DataHomeDirectory()
	if err != nil {
		return err
	}
	c.UserDataDir = path.Join(d, config.AppDir)
	c.BundleInstallDir = path.Join(c.UserDataDir, bundleInstallDir)

	// Create the relevant directories.
	for _, d = range []string{c.RuntimeDir, c.UserDataDir} {
		if err := os.MkdirAll(d, config.DirMode); err != nil {
			return err
		}
	}

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

// DoInstall executes the install step based on the configured parameters.
// This is blocking and should be run from a go routine, with the appropriate
// Async structure used to communicate.
func (c *Common) DoInstall(async *Async) {
	var err error
	async.Err = nil
	defer func() {
		if async.Err != nil {
			log.Printf("install: Failing with error: %v", async.Err)
		} else {
			log.Printf("install: Complete.")
		}
		runtime.GC()
		async.Done <- true
	}()

	log.Printf("install: Starting.")

	if c.tor != nil {
		log.Printf("install: Shutting down old tor.")
		c.tor.Shutdown()
		c.tor = nil
	}

	// Get the Dial() routine used to reach the external network.
	// XXX: Make this into a function...
	dialFn := net.Dial // No system tor, use direct connections.
	if c.Cfg.UseSystemTor {
		if c.tor, err = tor.NewSystemTor(c.Cfg.SystemTorControlNet, c.Cfg.SystemTorControlAddr); err != nil {
			async.Err = err
			return
		}

		// Query the socks port, setup the dialer.
		if dialer, err := c.tor.Dialer(); err != nil {
			async.Err = err
			return
		} else {
			dialFn = dialer.Dial
		}
	}

	// XXX: Wrap dialFn in a HPKP dialer.
	_ = dialFn

	// Create the async HTTP client.
	client := grab.NewClient()
	client.UserAgent = ""
	client.HTTPClient.Transport = &http.Transport{
		Proxy: nil,
		Dial:  dialFn,
	}

	// Download the JSON file showing where the bundle files are.
	log.Printf("install: Checking available downloads.")
	async.UpdateProgress("Checking available downloads.")

	var version string
	var downloads *installer.DownloadsEntry
	if url := installer.DownloadsURL(c.Cfg); url == "" {
		async.Err = fmt.Errorf("unable to find downloads URL")
		return
	} else if b := async.grab(client, url, nil); async.Err != nil {
		return
	} else if version, downloads, err = installer.GetDownloadsEntry(c.Cfg, b); err != nil {
		async.Err = err
		return
	}

	log.Printf("install: Version: %v Downloads: %v", version, downloads)

	// Download the bundle.
	log.Printf("install: Downloading %v", downloads.Binary)
	async.UpdateProgress("Downloading Tor Browser.")

	var bundleTarXz []byte
	if bundleTarXz = async.grab(client, downloads.Binary, func(s string) { async.UpdateProgress(fmt.Sprintf("Downloading Tor Browser: %s", s)) }); async.Err != nil {
		return
	}

	// Download the signature.
	log.Printf("install: Downloading %v", downloads.Sig)
	async.UpdateProgress("Downloading Tor Browser PGP Signature.")

	var bundleSig []byte
	if bundleSig = async.grab(client, downloads.Sig, nil); async.Err != nil {
		return
	}

	// Check the signature.
	log.Printf("install: Validating Tor Browser PGP Signature.")
	async.UpdateProgress("Validating Tor Browser PGP Signature.")

	if async.Err = installer.ValidatePGPSignature(bundleTarXz, bundleSig); async.Err != nil {
		return
	}

	// Install the bundle.
	log.Printf("install: Installing Tor Browser.")
	async.UpdateProgress("Installing Tor Browser.")

	if err := installer.ExtractBundle(c.BundleInstallDir, bundleTarXz, async.Cancel); err != nil {
		async.Err = err
		if async.Err == installer.ErrExtractionCanceled {
			async.Err = ErrCanceled
		}
		return
	}

	// Lock out and ignore cancelation, since things are basically done.
	async.Lock()
	defer async.Unlock()

	// XXX: Install the autoconfig stuff.

	// Set the manifest portion of the config.
	c.Cfg.SetInstalled(&config.Installed{
		Version:      version,
		Architecture: c.Cfg.Architecture,
		Channel:      c.Cfg.Channel,
		Locale:       c.Cfg.Locale,
	})

	// Sync the config, and return.
	async.Err = c.Cfg.Sync()
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
	p := path.Join(c.RuntimeDir, lockFileName)

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