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
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"git.schwanenlied.me/yawning/grab.git"
	"git.schwanenlied.me/yawning/hpkp.git"

	"cmd/sandboxed-tor-browser/internal/data"
	"cmd/sandboxed-tor-browser/internal/installer"
	"cmd/sandboxed-tor-browser/internal/sandbox"
	"cmd/sandboxed-tor-browser/internal/tor"
	. "cmd/sandboxed-tor-browser/internal/ui/async"
	"cmd/sandboxed-tor-browser/internal/ui/config"
	"cmd/sandboxed-tor-browser/internal/utils"
)

var (
	// BundleChannels is the map of Tor Browser architectures to channels.
	BundleChannels map[string][]string

	// BundleLocales is the map of Tor Browser channels to locales.
	BundleLocales map[string][]string

	// Bridges is the map of transports to Bridge lines.
	Bridges map[string][]string

	// Version is the version of `sandboxed-tor-browser`.
	Version string
)

const (
	// DefaultBridgeTransport is the decault bridge transport when using internal
	// bridges.
	DefaultBridgeTransport = "obfs4"

	chanHardened = "hardened"
)

func usage() {
	_, file := filepath.Split(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]... [COMMAND]\n", file)
	fmt.Fprintf(os.Stderr, "\n Options:\n\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "\n Commands:\n\n")
	fmt.Fprintf(os.Stderr, "   install\tForce (re)installation.\n")
	fmt.Fprintf(os.Stderr, "   config\tForce (re)configuration.\n")
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(-1)
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
	Cfg     *config.Config
	Manif   *config.Manifest
	Sandbox *exec.Cmd
	tor     *tor.Tor
	lock    *lockFile

	logQuiet bool
	logPath  string
	logFile  *os.File

	ForceInstall   bool
	ForceConfig    bool
	AdvancedConfig bool
	PrintVersion   bool
}

// Init initializes the common interface state.
func (c *Common) Init() error {
	var err error

	// Register the common command line flags.
	flag.Usage = usage
	flag.BoolVar(&c.AdvancedConfig, "advanced", false, "Show advanced config options.")
	flag.BoolVar(&c.PrintVersion, "version", false, "Print the version and exit.")
	flag.BoolVar(&c.logQuiet, "q", false, "Suppress logging to console.")
	flag.StringVar(&c.logPath, "l", "", "Specify a log file.")

	// Initialize/load the config file.
	if c.Cfg, err = config.New(); err != nil {
		return err
	}
	if c.Manif, err = config.LoadManifest(c.Cfg); err != nil {
		return err
	}
	c.Cfg.Sanitize()

	if sandbox.IsGrsecKernel() {
		channels := []string{}
		for _, v := range BundleChannels[c.Cfg.Architecture] {
			if v != "hardened" {
				channels = append(channels, v)
			}
		}
		BundleChannels[c.Cfg.Architecture] = channels
	}

	if c.Manif != nil {
		if err = c.Manif.Sync(); err != nil {
			return err
		}
	}
	return c.Cfg.Sync()
}

// Run handles initiailzing the at-runtime state.
func (c *Common) Run() error {
	const (
		cmdInstall = "install"
		cmdConfig  = "config"
	)

	// Parse the command line flags.
	flag.Parse()
	for _, v := range flag.Args() {
		switch strings.ToLower(v) {
		case cmdInstall:
			c.ForceInstall = true
		case cmdConfig:
			c.ForceConfig = true
		default:
			flag.Usage()
		}
	}
	if c.PrintVersion {
		fmt.Printf("sandboxed-tor-browser %s\n", Version)
		return nil // Skip the lock, because we will exit.
	}

	// Create the directories required.
	if !utils.DirExists(c.Cfg.UserDataDir) {
		// That's odd, there's a manifest even though there's no user data.
		if c.Manif != nil {
			c.Manif.Purge()
			c.Manif = nil
		}
		if err := os.MkdirAll(c.Cfg.UserDataDir, utils.DirMode); err != nil {
			return err
		}
	}
	if !utils.DirExists(c.Cfg.RuntimeDir) {
		if err := os.MkdirAll(c.Cfg.RuntimeDir, utils.DirMode); err != nil {
			return err
		}
	}

	// Setup logging.
	var err error
	logWriters := []io.Writer{}
	if c.logPath != "" {
		flags := os.O_CREATE | os.O_APPEND | os.O_WRONLY
		c.logFile, err = os.OpenFile(c.logPath, flags, utils.FileMode)
		if err != nil {
			fmt.Printf("Failed to open log file '%v': %v", c.logPath, err)
		}
		logWriters = append(logWriters, c.logFile)
	}
	if !c.logQuiet {
		logWriters = append(logWriters, os.Stdout)
	}
	if len(logWriters) == 0 {
		log.SetOutput(ioutil.Discard)
	} else {
		w := io.MultiWriter(logWriters...)
		log.SetOutput(w)
	}

	// Acquire the lock file.
	if c.lock, err = newLockFile(c); err != nil {
		return err
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

// NeedsInstall returns true if the bundle needs to be (re)installed.
func (c *Common) NeedsInstall() bool {
	if c.Manif == nil {
		return true
	}
	if c.Manif.Architecture != c.Cfg.Architecture {
		return true
	}
	if c.Manif.Channel != c.Cfg.Channel {
		return true
	}
	if c.Manif.Locale != c.Cfg.Locale {
		return true
	}
	return false
}

type dialFunc func(string, string) (net.Conn, error)

func (c *Common) launchTor(async *Async, onlySystem bool) (dialFunc, error) {
	var err error
	defer func() {
		if async.Err != nil && c.tor != nil {
			c.tor.Shutdown()
			c.tor = nil
		}
	}()

	if c.tor != nil {
		log.Printf("launch: Shutting down old tor.")
		c.tor.Shutdown()
		c.tor = nil
	}

	if c.Cfg.UseSystemTor {
		if c.tor, err = tor.NewSystemTor(c.Cfg); err != nil {
			async.Err = err
			return nil, err
		}
	} else if !onlySystem {
		// Build the torrc.
		torrc, err := tor.CfgToSandboxTorrc(c.Cfg, Bridges)
		if err != nil {
			async.Err = err
			return nil, err
		}

		os.Remove(filepath.Join(c.Cfg.TorDataDir, "control_port"))

		async.UpdateProgress("Launching Tor executable.")
		cmd, err := sandbox.RunTor(c.Cfg, torrc)
		if err != nil {
			async.Err = err
			return nil, err
		}

		async.UpdateProgress("Waiting on Tor bootstrap.")
		c.tor = tor.NewSandboxedTor(c.Cfg, cmd)
		if err = c.tor.DoBootstrap(c.Cfg, async); err != nil {
			async.Err = err
			return nil, err
		}
	} else if !(c.NeedsInstall() || c.ForceInstall) {
		// That's odd, we only asked for a system tor, but we should be capable
		// of launching tor ourselves.  Don't use a direct connection.
		err = fmt.Errorf("tor bootstrap would be skipped, when we could launch")
		async.Err = err
		return nil, err
	}

	// If we managed to launch tor...
	if c.tor != nil {
		// Query the socks port, setup the dialer.
		if dialer, err := c.tor.Dialer(); err != nil {
			async.Err = err
			return nil, err
		} else {
			return dialer.Dial, nil
		}
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
	p := filepath.Join(c.Cfg.RuntimeDir, lockFileName)

	var err error
	if l.f, err = os.OpenFile(p, os.O_CREATE|os.O_EXCL, utils.FileMode); err != nil {
		return nil, err
	}
	return l, nil
}

// ValidateBridgeLines validates and sanitizes bridge lines.
func ValidateBridgeLines(ls string) (string, error) {
	var ret []string

	for _, l := range strings.Split(ls, "\n") {
		l = strings.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		sp := strings.Split(l, " ")
		if len(sp) == 0 {
			continue
		}
		if strings.ToLower(sp[0]) == "bridge" { // Assume well formed...
			ret = append(ret, l)
			continue
		}

		// XXX: This obliterates the user's changes if there's an error,
		// which is probably likely somewhat obnoxious.

		// Validate that there is at least either:
		if ip, _, err := net.SplitHostPort(sp[0]); err != nil {
			if net.ParseIP(sp[0]) != nil {
				return "", fmt.Errorf("invalid Bridge: '%v', missing port", l)
			}
			if Bridges[sp[0]] == nil {
				return "", fmt.Errorf("invalid Bridge: '%v', unknown transport: %v", l, sp[0])
			}
			if len(sp) < 2 {
				return "", fmt.Errorf("invalid Bridge: '%v', missing IP", l)
			}
			if ip, _, err = net.SplitHostPort(sp[1]); err != nil {
				return "", fmt.Errorf("invalid Bridge: '%v', bad IP/port", l)
			} else if net.ParseIP(ip) == nil {
				return "", fmt.Errorf("invalid Bridge: '%v'", l)
			}
		} else if net.ParseIP(ip) == nil { // Or a host:port.
			return "", fmt.Errorf("invalid Bridge IP/port: %v", sp[0])
		}

		// BridgeDB entries lack the "Bridge".
		ret = append(ret, "Bridge "+l)
	}

	return strings.Join(ret, "\n"), nil
}

func newGrabClient(dialFn dialFunc, dialTLSFn dialFunc) *grab.Client {
	// Create the async HTTP client.
	client := grab.NewClient()
	client.UserAgent = ""
	client.HTTPClient.Transport = &http.Transport{
		Proxy:   nil,
		Dial:    dialFn,
		DialTLS: dialTLSFn,
	}
	return client
}

func newHPKPGrabClient(dialFn dialFunc) *grab.Client {
	dialConf := &hpkp.DialerConfig{
		Storage:   installer.StaticHPKPPins,
		PinOnly:   false,
		TLSConfig: nil,
		Dial:      dialFn,
	}
	return newGrabClient(dialFn, dialConf.NewDialer())
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

	// Cowardly refuse to allow the user to install the hardeened bundle on
	// grsec kernels.
	if sandbox.IsGrsecKernel() {
		delete(BundleLocales, chanHardened)
	}

	Bridges = make(map[string][]string)
	if d, err := data.Asset("bridges.json"); err != nil {
		panic(err)
	} else if err = json.Unmarshal(d, &Bridges); err != nil {
		panic(err)
	}

	if d, err := data.Asset("version"); err != nil {
		panic(err)
	} else {
		Version = strings.TrimSpace(string(d))
	}

	// Fixup all the bridge lines to be well formed.
	for _, bridges := range Bridges {
		for i, v := range bridges {
			bridges[i] = "Bridge " + v
		}
	}
}
