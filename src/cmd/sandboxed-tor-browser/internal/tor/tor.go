// tor.go - Tor daemon interface routines.
// Copyright (C) 2015, 2016  Yawning Angel.
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

// Package tor provides an interface for controlling and using a tor daemon.
package tor

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"git.schwanenlied.me/yawning/bulb.git"
	"golang.org/x/net/proxy"
)

// ErrTorNotRunning is the error returned when the tor is not running.
var ErrTorNotRunning = errors.New("tor not running")

// Tor is a tor instance.
type Tor struct {
	sync.Mutex

	isSystem bool

	cmd  *exec.Cmd
	ctrl *bulb.Conn
}

// IsSystem returns if the tor instance is a OS service not being actively
// managed by the app.
func (t *Tor) IsSystem() bool {
	return t.isSystem
}

// Dialer returns a proxy.Dialer configured to use the Socks port with the
// generic `sandboxed-tor-browser:isolation:pid` isolation settings.
func (t *Tor) Dialer() (proxy.Dialer, error) {
	t.Lock()
	defer t.Unlock()

	if t.ctrl == nil {
		return nil, ErrTorNotRunning
	}
	auth := &proxy.Auth{
		User:     "sandboxed-tor-bowser",
		Password: "isolation:" + strconv.Itoa(os.Getpid()),
	}
	return t.ctrl.Dialer(auth)
}

// SocksPort returns the SocksPort associated with the tor instance.
func (t *Tor) SocksPort() (net, addr string, err error) {
	t.Lock()
	defer t.Unlock()

	if t.ctrl == nil {
		return "", "", ErrTorNotRunning
	}
	return t.ctrl.SocksPort()
}

// Newnym issues a `SIGNAL NWENYM`.
func (t *Tor) Newnym() error {
	t.Lock()
	defer t.Unlock()

	if t.ctrl == nil {
		return ErrTorNotRunning
	}
	_, err := t.ctrl.Request("SIGNAL NEWNYM")
	return err
}

// Shutdown attempts to gracefully clean up the Tor instance.  If it is a
// system tor, only the control port connection will be closed.  Otherwise,
// the tor daemon will be SIGTERMed.
func (t *Tor) Shutdown() {
	t.Lock()
	defer t.Unlock()

	if t.ctrl != nil {
		t.ctrl.Close()
		t.ctrl = nil
	}

	if t.cmd != nil {
		t.cmd.Process.Signal(syscall.SIGTERM)
		t.ctrl = nil
	}
}

// NewSystemTor creates a Tor struct around a system tor instance.
func NewSystemTor(net, addr string) (*Tor, error) {
	t := new(Tor)
	t.isSystem = true

	// Dial the control port.
	var err error
	if t.ctrl, err = bulb.Dial(net, addr); err != nil {
		return nil, err
	}

	// Authenticate with the control port.
	if err = t.ctrl.Authenticate(""); err != nil {
		t.ctrl.Close()
		return nil, err
	}

	return t, nil
}
