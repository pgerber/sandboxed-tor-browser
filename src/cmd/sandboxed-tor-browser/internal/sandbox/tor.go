// sandbox.go - Tor related sandbox routines.
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

package sandbox

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"cmd/sandboxed-tor-browser/internal/socks5"
	"cmd/sandboxed-tor-browser/internal/tor"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

const (
	cmdProtocolInfo  = "PROTOCOLINFO"
	cmdAuthenticate  = "AUTHENTICATE"
	cmdAuthChallenge = "AUTHCHALLENGE"
	cmdQuit          = "QUIT"
	cmdGetInfo       = "GETINFO"
	cmdSignal        = "SIGNAL"

	responseOk = "250 OK\r\n"

	errAuthenticationRequired = "514 Authentication required\r\n"
	errUnrecognizedCommand    = "510 Unrecognized command\r\n"
	errUnspecifiedTor         = "550 Unspecified Tor error\r\n"

	// These responses are entirely synthetic so they don't matter.
	torVersion = "0.2.8.7"
	socksAddr  = "127.0.0.1:9150"
)

type socksProxy struct {
	sync.RWMutex
	sNet, sAddr string
	tag         string

	l net.Listener
}

func (p *socksProxy) newTag() error {
	p.Lock()
	defer p.Unlock()

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	p.tag = "sandboxed-tor-browser:" + hex.EncodeToString(b[:])

	return nil
}

func (p *socksProxy) acceptLoop() {
	defer p.l.Close()

	for {
		conn, err := p.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			log.Printf("failed to accept SOCKS conn: %v", err)
			return
		}
		go p.handleConn(conn)
	}
}

func (p *socksProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	// Do the SOCKS5 protocol chatter with the application.
	req, err := socks5.Handshake(conn)
	if err != nil {
		return
	}

	// Append our isolation tag.
	if err := p.rewriteTag(conn, req); err != nil {
		req.Reply(socks5.ReplyGeneralFailure)
		return
	}

	// Redispatch the modified SOCKS5 request upstream.
	upConn, err := socks5.Redispatch(p.sNet, p.sAddr, req)
	if err != nil {
		req.Reply(socks5.ErrorToReplyCode(err))
		return
	}
	defer upConn.Close()

	// Complete the SOCKS5 handshake with the app.
	if err := req.Reply(socks5.ReplySucceeded); err != nil {
		return
	}

	p.copyLoop(upConn, conn)
}

func (p *socksProxy) rewriteTag(conn net.Conn, req *socks5.Request) error {
	p.RLock()
	defer p.RUnlock()
	if req.Auth.Uname == nil {
		// If the socks request ever isn't using username/password isolation,
		// fail the request, since it's an upstream bug, instead of trying to
		// do a kludgy workaround.
		//
		// See https://bugs.torproject.org/20195
		return fmt.Errorf("invalid isolation requested by Tor Browser")
	}
	req.Auth.Passwd = append(req.Auth.Passwd, []byte(":"+p.tag)...)
	// With the current format this should never happen, ever.
	if len(req.Auth.Passwd) > 255 {
		return fmt.Errorf("failed to redispatch, socks5 password too long")
	}
	return nil
}

func (p *socksProxy) copyLoop(upConn, downConn net.Conn) {
	errChan := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	cpFn := func(a, b net.Conn) {
		defer wg.Done()
		defer a.Close()
		defer b.Close()

		_, err := io.Copy(a, b)
		errChan <- err
	}

	go cpFn(upConn, downConn)
	go cpFn(downConn, upConn)

	wg.Wait()
}

func launchSocksProxy(cfg *config.Config, tor *tor.Tor) (*socksProxy, error) {
	p := new(socksProxy)
	if err := p.newTag(); err != nil {
		return nil, err
	}

	var err error
	p.sNet, p.sAddr, err = tor.SocksPort()
	if err != nil {
		return nil, err
	}

	sPath := path.Join(cfg.RuntimeDir, socksSocket)
	os.Remove(sPath)
	p.l, err = net.Listen("unix", sPath)
	if err != nil {
		return nil, err
	}

	go p.acceptLoop()

	return p, nil
}

type ctrlProxyConn struct {
	socks         *socksProxy
	tor           *tor.Tor
	appConn       net.Conn
	appConnReader *bufio.Reader
	isPreAuth     bool
}

func (c *ctrlProxyConn) appConnWrite(b []byte) (int, error) {
	return c.appConn.Write(b)
}

func (c *ctrlProxyConn) appConnReadLine() (cmd string, splitCmd []string, rawLine []byte, err error) {
	if rawLine, err = c.appConnReader.ReadBytes('\n'); err != nil {
		return
	}

	trimmedLine := bytes.TrimSpace(rawLine)
	splitCmd = strings.Split(string(trimmedLine), " ")
	cmd = strings.ToUpper(strings.TrimSpace(splitCmd[0]))
	return
}

func (c *ctrlProxyConn) processPreAuth() error {
	sentProtocolInfo := false
	for {
		cmd, splitCmd, _, err := c.appConnReadLine()
		if err != nil {
			return err
		}

		switch cmd {
		case cmdProtocolInfo:
			if sentProtocolInfo {
				c.sendErrAuthenticationRequired()
				return errors.New("client already sent PROTOCOLINFO already")
			}
			sentProtocolInfo = true
			if err = c.onCmdProtocolInfo(splitCmd); err != nil {
				return err
			}
		case cmdAuthenticate:
			_, err = c.appConnWrite([]byte(responseOk))
			c.isPreAuth = false
			return err
		case cmdAuthChallenge:
			// WTF?  We should never see this since PROTOCOLINFO lies about the
			// supported authentication types.
			c.sendErrUnrecognizedCommand()
			return errors.New("client sent AUTHCHALLENGE, when not supported")
		case cmdQuit:
			return errors.New("client requested connection close")
		default:
			c.sendErrAuthenticationRequired()
			return fmt.Errorf("invalid app command: '%s'", cmd)
		}
	}
	return nil
}

func (c *ctrlProxyConn) proxyAndFilerApp() {
	defer c.appConn.Close()

	for {
		cmd, splitCmd, raw, err := c.appConnReadLine()
		if err != nil {
			break
		}

		switch cmd {
		case cmdProtocolInfo:
			err = c.onCmdProtocolInfo(splitCmd)
		case cmdGetInfo:
			err = c.onCmdGetInfo(splitCmd, raw)
		case cmdSignal:
			err = c.onCmdSignal(splitCmd, raw)
		default:
			err = c.sendErrUnrecognizedCommand()
		}
		if err != nil {
			break
		}
	}
}

func (c *ctrlProxyConn) sendErrAuthenticationRequired() error {
	_, err := c.appConnWrite([]byte(errAuthenticationRequired))
	return err
}

func (c *ctrlProxyConn) sendErrUnrecognizedCommand() error {
	_, err := c.appConnWrite([]byte(errUnrecognizedCommand))
	return err
}

func (c *ctrlProxyConn) sendErrUnspecifiedTor() error {
	_, err := c.appConnWrite([]byte(errUnspecifiedTor))
	return err
}

func (c *ctrlProxyConn) sendErrUnexpectedArgCount(cmd string, expected, actual int) error {
	var err error
	var respStr string
	if expected > actual {
		respStr = "512 Too many arguments to " + cmd + "\r\n"
	} else {
		respStr = "512 Missing argument to " + cmd + "\r\n"
	}
	_, err = c.appConnWrite([]byte(respStr))
	return err
}

func (c *ctrlProxyConn) onCmdProtocolInfo(splitCmd []string) error {
	for i := 1; i < len(splitCmd); i++ {
		v := splitCmd[i]
		if _, err := strconv.ParseInt(v, 10, 32); err != nil {
			respStr := "513 No such version \"" + v + "\"\r\n"
			_, err := c.appConnWrite([]byte(respStr))
			return err
		}
	}
	respStr := "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL,HASHEDPASSWORD\r\n250-VERSION Tor=\"" + torVersion + "\"\r\n" + responseOk
	_, err := c.appConnWrite([]byte(respStr))
	return err
}

func (c *ctrlProxyConn) onCmdGetInfo(splitCmd []string, raw []byte) error {
	const argGetInfoSocks = "net/listeners/socks"
	if len(splitCmd) != 2 {
		return c.sendErrUnexpectedArgCount(cmdGetInfo, 2, len(splitCmd))
	} else if splitCmd[1] != argGetInfoSocks {
		respStr := "552 Unrecognized key \"" + splitCmd[1] + "\"\r\n"
		_, err := c.appConnWrite([]byte(respStr))
		return err
	} else {
		respStr := "250-" + argGetInfoSocks + "=\"" + socksAddr + "\"\r\n" + responseOk
		_, err := c.appConnWrite([]byte(respStr))
		return err
	}
}

func (c *ctrlProxyConn) onCmdSignal(splitCmd []string, raw []byte) error {
	const argSignalNewnym = "NEWNYM"
	if len(splitCmd) != 2 {
		return c.sendErrUnexpectedArgCount(cmdSignal, 2, len(splitCmd))
	} else if splitCmd[1] != argSignalNewnym {
		respStr := "552 Unrecognized signal code \"" + splitCmd[1] + "\"\r\n"
		_, err := c.appConnWrite([]byte(respStr))
		return err
	} else {
		if err := c.socks.newTag(); err != nil {
			return c.sendErrUnspecifiedTor()
		}
		if err := c.tor.Newnym(); err != nil {
			return c.sendErrUnspecifiedTor()
		}
		_, err := c.appConnWrite([]byte(responseOk))
		return err
	}
}

func (c *ctrlProxyConn) handle() {
	defer c.appConn.Close()

	var err error
	if err = c.processPreAuth(); err != nil {
		log.Printf("control port pre-auth error: %v", err)
		return
	}

	c.proxyAndFilerApp()
}

type ctrlProxy struct {
	socks *socksProxy
	tor   *tor.Tor

	l net.Listener
}

func (p *ctrlProxy) acceptLoop() {
	defer p.l.Close()

	for {
		conn, err := p.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			log.Printf("failed to accept control conn: %v", err)
			return
		}
		p.handleConn(conn)
	}
}

func (p *ctrlProxy) handleConn(conn net.Conn) {
	c := &ctrlProxyConn{
		socks:         p.socks,
		tor:           p.tor,
		appConn:       conn,
		appConnReader: bufio.NewReader(conn),
	}
	go c.handle()
}

func launchCtrlProxy(cfg *config.Config, socks *socksProxy, tor *tor.Tor) error {
	p := new(ctrlProxy)
	p.socks = socks
	p.tor = tor

	var err error
	cPath := path.Join(cfg.RuntimeDir, controlSocket)
	os.Remove(cPath)
	p.l, err = net.Listen("unix", cPath)
	if err != nil {
		return err
	}
	go p.acceptLoop()

	return nil
}
