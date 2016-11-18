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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	//	mrand "math/rand"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"git.schwanenlied.me/yawning/bulb.git"
	"golang.org/x/crypto/openpgp/s2k"
	"golang.org/x/net/proxy"

	"cmd/sandboxed-tor-browser/internal/data"
	. "cmd/sandboxed-tor-browser/internal/ui/async"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

// ErrTorNotRunning is the error returned when the tor is not running.
var ErrTorNotRunning = errors.New("tor not running")

// Tor is a tor instance.
type Tor struct {
	sync.Mutex

	isSystem bool

	cmd        *exec.Cmd
	ctrl       *bulb.Conn
	ctrlEvents chan *bulb.Response

	socksNet  string
	socksAddr string

	ctrlSurrogate  *ctrlProxy
	socksSurrogate *socksProxy
}

// IsSystem returns if the tor instance is a OS service not being actively
// managed by the app.
func (t *Tor) IsSystem() bool {
	return t.isSystem
}

// Dialer returns a proxy.Dialer configured to use the Socks port with the
// generic `sandboxed-tor-browser:isolation:pid` isolation settings.
func (t *Tor) Dialer() (proxy.Dialer, error) {
	net, addr, err := t.SocksPort()
	if err != nil {
		return nil, err
	}

	t.Lock()
	defer t.Unlock()

	if t.ctrl == nil {
		return nil, ErrTorNotRunning
	}
	auth := &proxy.Auth{
		User:     "sandboxed-tor-bowser",
		Password: "isolation:" + strconv.Itoa(os.Getpid()),
	}

	return proxy.SOCKS5(net, addr, auth, proxy.Direct)
}

// SocksPort returns the SocksPort associated with the tor instance.
func (t *Tor) SocksPort() (net, addr string, err error) {
	t.Lock()
	defer t.Unlock()

	if t.ctrl == nil {
		return "", "", ErrTorNotRunning
	}
	if t.socksNet == "" && t.socksAddr == "" {
		t.socksNet, t.socksAddr, err = t.ctrl.SocksPort()
	}
	return t.socksNet, t.socksAddr, err
}

func (t *Tor) newnym() error {
	t.Lock()
	defer t.Unlock()

	if t.ctrl == nil {
		return ErrTorNotRunning
	}
	_, err := t.ctrl.Request("SIGNAL NEWNYM")
	return err
}

func (t *Tor) getinfo(arg string) (*bulb.Response, error) {
	t.Lock()
	defer t.Unlock()

	if t.ctrl == nil {
		return nil, ErrTorNotRunning
	}
	return t.ctrl.Request("GETINFO %s", arg)
}

func (t *Tor) getconf(arg string) (*bulb.Response, error) {
	t.Lock()
	defer t.Unlock()

	if t.ctrl == nil {
		return nil, ErrTorNotRunning
	}
	return t.ctrl.Request("GETCONF %s", arg)
}

// Shutdown attempts to gracefully clean up the Tor instance.  If it is a
// system tor, only the control port connection will be closed.  Otherwise,
// the tor daemon will be SIGTERMed.
func (t *Tor) Shutdown() {
	t.Lock()
	defer t.Unlock()

	if t.ctrl != nil {
		// Try extra hard to get tor to fuck off, if we spawned it.
		if !t.isSystem {
			t.ctrl.Request("SIGNAL HALT")
		}
		t.ctrl.Close()
		t.ctrl = nil
	}

	if t.cmd != nil {
		t.cmd.Process.Signal(syscall.SIGTERM)
		t.ctrl = nil
	}

	if t.ctrlSurrogate != nil {
		t.ctrlSurrogate.close()
		t.ctrlSurrogate = nil
	}

	if t.socksSurrogate != nil {
		t.socksSurrogate.close()
		t.socksSurrogate = nil
	}
}

// SocksSurrogatePath returns the socks port surrogate AF_UNIX path.
func (t *Tor) SocksSurrogatePath() string {
	return t.socksSurrogate.sPath
}

// CtrlSurrogatePath returns the control port surrogate AF_UNIX path.
func (t *Tor) CtrlSurrogatePath() string {
	return t.ctrlSurrogate.cPath
}

func (t *Tor) launchSurrogates(cfg *config.Config) error {
	var err error
	if t.socksSurrogate, err = launchSocksProxy(cfg, t); err != nil {
		return err
	}

	if t.ctrlSurrogate, err = launchCtrlProxy(cfg, t); err != nil {
		t.socksSurrogate.close()
		return err
	}
	return nil
}

func (t *Tor) eventReader() {
	for {
		resp, err := t.ctrl.NextEvent()
		if err != nil {
			break
		}
		t.ctrlEvents <- resp
	}
	close(t.ctrlEvents)
}

// NewSystemTor creates a Tor struct around a system tor instance.
func NewSystemTor(cfg *config.Config) (*Tor, error) {
	t := new(Tor)
	t.isSystem = true
	t.ctrlEvents = make(chan *bulb.Response, 16)

	net := cfg.SystemTorControlNet
	addr := cfg.SystemTorControlAddr

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

	t.ctrl.StartAsyncReader()
	go t.eventReader()

	// Launch the surrogates.
	if err = t.launchSurrogates(cfg); err != nil {
		t.ctrl.Close()
		return nil, err
	}

	return t, nil
}

// NewSandboxedTor creates a Tor struct around a sandboxed tor instance,
// and boostraps.
func NewSandboxedTor(cfg *config.Config, async *Async, cmd *exec.Cmd) (t *Tor, err error) {
	var torCleanup *Tor
	defer func() { // Automagically handle async error propagation.
		if err != nil {
			async.Err = err
			if torCleanup != nil {
				torCleanup.Shutdown()
			}
		}
	}()

	t = new(Tor)
	torCleanup = t
	t.isSystem = false
	t.cmd = cmd
	t.socksNet = "unix"
	t.socksAddr = path.Join(cfg.TorDataDir, "socks")
	t.ctrlEvents = make(chan *bulb.Response, 16)

	hz := time.NewTicker(1 * time.Second)
	defer hz.Stop()

	// Wait for the control port to be ready.
	var ctrlPortAddr []byte
	for nTicks := 0; nTicks < 10; { // 10 sec timeout (control port).
		if ctrlPortAddr, err = ioutil.ReadFile(path.Join(cfg.TorDataDir, "control_port")); err == nil {
			break
		}

		if os.IsNotExist(err) {
			select {
			case <-hz.C:
				nTicks++
				continue
			case <-async.Cancel:
				return nil, ErrCanceled
			}
		}
		return nil, err
	}
	if ctrlPortAddr == nil {
		return nil, fmt.Errorf("tor: timeout waiting for the control port")
	}

	log.Printf("tor: control port is: %v", string(ctrlPortAddr))

	// Dial the control port.
	async.UpdateProgress("Connecting to the Tor Control Port.")
	if t.ctrl, err = bulb.Dial("unix", path.Join(cfg.TorDataDir, "control")); err != nil {
		return nil, err
	}

	// Authenticate with the control port.
	if err = t.ctrl.Authenticate(cfg.Tor.CtrlPassword); err != nil {
		return nil, err
	}

	// Take ownership of the tor process such that it will self terminate
	// when the control port connection gets closed.  Past this point, tor
	// shouldn't leave a turd process lying around, though I've seen it on
	// occaision. :(
	log.Printf("tor: Taking ownership of the tor process")
	if _, err = t.ctrl.Request("TAKEOWNERSHIP"); err != nil {
		return nil, err
	}

	// Start the event async reader.
	t.ctrl.StartAsyncReader()
	go t.eventReader()

	// Register the `STATUS_CLIENT` event handler.
	if _, err = t.ctrl.Request("SETEVENTS STATUS_CLIENT"); err != nil {
		return nil, err
	}

	// Start the bootstrap.
	async.UpdateProgress("Connecting to the Tor network.")
	if _, err = t.ctrl.Request("RESETCONF DisableNetwork"); err != nil {
		return nil, err
	}

	// Wait for bootstrap to finish.
	bootstrapFinished := false
	for nTicks := 0; nTicks < 120 && !bootstrapFinished; { // 120 sec timeout (bootstrap).
		select {
		case ev := <-t.ctrlEvents:
			const evPrefix = "STATUS_CLIENT "
			if !strings.HasPrefix(ev.Reply, evPrefix) {
				continue
			}
			bootstrapFinished = handleBootstrapEvent(async, strings.TrimPrefix(ev.Reply, evPrefix))
		case <-async.Cancel:
			return nil, ErrCanceled
		case <-hz.C:
			const statusPrefix = "status/bootstrap-phase="

			// As a fallback, use kill(pid, 0) to detect if the process has
			// puked.  waitpid(2) is probably better since it's a child, but
			// this should be good enough, and is only to catch tor crashing.
			if err := syscall.Kill(cmd.Process.Pid, 0); err == syscall.ESRCH {
				return nil, fmt.Errorf("tor process appears to have crashed.")
			}

			// Fallback in case something goes wrong, poll the bootstrap status
			// every 10 sec.
			nTicks++
			if nTicks%10 != 0 {
				continue
			}

			resp, err := t.getinfo("status/bootstrap-phase")
			if err != nil {
				return nil, err
			}
			bootstrapFinished = handleBootstrapEvent(async, strings.TrimPrefix(resp.Data[0], statusPrefix))
		}
	}
	if !bootstrapFinished {
		return nil, fmt.Errorf("tor: timeout connecting to the tor network")
	}

	// Squelch the events, and drain the event queue.
	if _, err = t.ctrl.Request("SETEVENTS"); err != nil {
		return nil, err
	}
	for len(t.ctrlEvents) > 0 {
		<-t.ctrlEvents
	}

	// Launch the surrogates.
	if err = t.launchSurrogates(cfg); err != nil {
		return nil, err
	}

	return t, nil
}

// CfgToSandboxTorrc converts the `ui/config/Config` to a sandboxed tor ready
// torrc.
func CfgToSandboxTorrc(cfg *config.Config, bridges map[string][]string) ([]byte, error) {
	torrc, err := data.Asset("torrc")
	if err != nil {
		return nil, err
	}

	// Apply proxy/bridge config.
	if cfg.Tor.UseBridges {
		bridgeArgs := []string{
			"UseBridges 1",
			"ClientTransportPlugin obfs2,obfs3,obfs4,scramblesuit exec /home/amnesia/tor/bin/PluggableTransports/obfs4proxy",
		}
		if !cfg.Tor.UseCustomBridges {
			// XXX: Actually shuffle this once there's a mechanism for
			// persisting ordering. (#43)
			for _, v := range bridges[cfg.Tor.InternalBridgeType] {
				bridgeArgs = append(bridgeArgs, v)
			}
			/*
				shuf := mrand.Perm(len(bridges[cfg.Tor.InternalBridgeType]))
				for _, i := range shuf {
					bridgeArgs = append(bridgeArgs, bridges[cfg.Tor.InternalBridgeType][i])
				}
			*/
		} else {
			// The caller is responsible for making sure that this is indeed
			// bridge lines, and not random other bullshit.
			bridgeArgs = append(bridgeArgs, cfg.Tor.CustomBridges)
		}

		s := "\n" + strings.Join(bridgeArgs, "\n") + "\n"
		torrc = append(torrc, []byte(s)...)
	} else {
		// Tor's built in seccomp whitelist based sandbox only works when
		// there are no managed pluggable transports, so only enable it when
		// bridges aren't in use.  The standard whitelist will have to
		// suffice when people use bridges.
		torrc = append(torrc, []byte("\nSandbox 1\n")...)
	}

	if cfg.Tor.UseProxy {
		proxyArgs := []string{}
		proxyAddr := cfg.Tor.ProxyAddress + ":" + cfg.Tor.ProxyPort
		proxyUser := cfg.Tor.ProxyUsername
		proxyPasswd := cfg.Tor.ProxyPassword

		switch cfg.Tor.ProxyType {
		case "SOCKS 4":
			proxyArgs = append(proxyArgs, "Socks4Proxy "+proxyAddr)
		case "SOCKS 5":
			proxyArgs = append(proxyArgs, "Socks5Proxy "+proxyAddr)
			if proxyUser != "" && proxyPasswd != "" {
				proxyArgs = append(proxyArgs, "Socks5ProxyUsername "+proxyUser)
				proxyArgs = append(proxyArgs, "Socks5ProxyPassword "+proxyPasswd)
			}
		case "HTTP(S)":
			proxyArgs = append(proxyArgs, "HTTPSProxy "+proxyAddr)
			if proxyUser != "" && proxyPasswd != "" {
				proxyArgs = append(proxyArgs, "HTTPSProxyAuthenticator "+proxyUser+":"+proxyPasswd)
			}
		default:
			return nil, fmt.Errorf("tor: Unsupported proxy type: %v", cfg.Tor.ProxyType)
		}

		s := "\n" + strings.Join(proxyArgs, "\n") + "\n"
		torrc = append(torrc, []byte(s)...)
	}

	// Generate a random control port password.
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, fmt.Errorf("tor: Failed to generate a password: %v", err)
	}
	cfg.Tor.CtrlPassword = hex.EncodeToString(entropy[:])

	// Convert it to the RFC2440 S2K variant that Tor understands and expects.
	// (SHA1, with the first 2 bytes of the descriptor that specify
	// iterated/salted, and the hash omitted).
	b := &bytes.Buffer{}
	key := make([]byte, 20)
	if err := s2k.Serialize(b, key, rand.Reader, []byte(cfg.Tor.CtrlPassword), nil); err != nil {
		return nil, fmt.Errorf("tor: Failed to hash password: %v", err)
	}
	b.Write(key)
	hashedPasswd := "16:" + hex.EncodeToString(b.Bytes()[2:])

	torrc = append(torrc, []byte("\nHashedControlPassword ")...)
	torrc = append(torrc, []byte(hashedPasswd)...)

	return torrc, nil
}

func handleBootstrapEvent(async *Async, s string) bool {
	const bootstrapPrefix = "NOTICE BOOTSTRAP "
	if !strings.HasPrefix(s, bootstrapPrefix) {
		return false
	}

	split := splitQuoted(strings.TrimPrefix(s, bootstrapPrefix))

	var progress, summary string
	for _, v := range split {
		const (
			progressPrefix = "PROGRESS="
			summaryPrefix  = "SUMMARY="
		)

		if strings.HasPrefix(v, progressPrefix) {
			progress = strings.TrimPrefix(v, progressPrefix)
		} else if strings.HasPrefix(v, summaryPrefix) {
			summary = strings.TrimPrefix(v, summaryPrefix)
			summary = strings.Trim(summary, "\"")
		}
	}
	if progress != "" && summary != "" {
		async.UpdateProgress(fmt.Sprintf("Bootstrap: %s", summary))
		if progress == "100" {
			return true
		}
	}
	return false
}

// Random quoted split function stolen and modified from the intertubes.
// https://groups.google.com/forum/#!topic/golang-nuts/pNwqLyfl2co
func splitQuoted(s string) []string {
	lastQuote := rune(0)
	f := func(c rune) bool {
		switch {
		case c == lastQuote:
			lastQuote = rune(0)
			return false
		case lastQuote != rune(0):
			return false
		case c == '"':
			lastQuote = c
			return false
		default:
			return unicode.IsSpace(c)
		}
	}

	return strings.FieldsFunc(s, f)
}
