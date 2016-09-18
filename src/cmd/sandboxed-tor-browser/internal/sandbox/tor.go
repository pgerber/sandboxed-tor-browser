// sandbox.go - Tor related sandbox routines.
// Copyright (C) 2016  Yawning Angel.
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/.

package sandbox

import (
	"bufio"
	"bytes"
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

	"cmd/sandboxed-tor-browser/internal/config"

	"git.schwanenlied.me/yawning/bulb.git"
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

	// These responses are entirely synthetic so they don't matter.
	torVersion = "0.2.8.7"
	socksAddr  = "127.0.0.1:9150"
)

func socksAcceptLoop(l net.Listener, sNet, sAddr string) {
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			log.Printf("failed to accept SOCKS conn: %v", err)
			return
		}
		go socksCopyLoop(conn, sNet, sAddr)
	}
}

func socksCopyLoop(downConn net.Conn, sNet, sAddr string) {
	defer downConn.Close()

	upConn, err := net.Dial(sNet, sAddr)
	if err != nil {
		log.Printf("failed to dial upstream SOCKS: %v", err)
		return
	}

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

func launchSocksProxy(cfg *config.Config) error {
	ctrl, err := cfg.DialControlPort()
	if err != nil {
		return err
	}
	defer ctrl.Close()

	sNet, sAddr, err := ctrl.SocksPort()
	if err != nil {
		return err
	}

	log.Printf("upstream socks port is: %v:%v", sNet, sAddr)

	sPath := path.Join(cfg.RuntimeDir(), socksSocket)
	os.Remove(sPath)
	l, err := net.Listen("unix", sPath)
	if err != nil {
		return err
	}

	go socksAcceptLoop(l, sNet, sAddr)

	return nil
}

type ctrlProxyConn struct {
	cfg           *config.Config
	ctrlConn      *bulb.Conn
	appConn       net.Conn
	appConnReader *bufio.Reader
	isPreAuth     bool
}

func newCtrlProxyConn(cfg *config.Config, conn net.Conn) *ctrlProxyConn {
	return &ctrlProxyConn{
		cfg:           cfg,
		appConn:       conn,
		appConnReader: bufio.NewReader(conn),
	}
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
		// We only bother opening the upstream control conn if it's required.
		if c.ctrlConn != nil {
			resp, err := c.ctrlConn.Request("SIGNAL NEWNYM")
			if err != nil {
				return err
			}
			for _, l := range resp.RawLines {
				if _, err := c.appConnWrite([]byte(l + "\r\n")); err != nil {
					return err
				}
			}
			return nil
		} else {
			_, err := c.appConnWrite([]byte(responseOk))
			return err
		}
	}
}

func (c *ctrlProxyConn) handle() {
	defer c.appConn.Close()

	var err error
	if err = c.processPreAuth(); err != nil {
		log.Printf("control port pre-auth error: %v", err)
		return
	}

	// The alpha and hardened channels as of recent builds don't need to send a
	// NEWNYM on New Identity since I fixed the behavior.
	if c.cfg.Channel == "release" {
		if c.ctrlConn, err = c.cfg.DialControlPort(); err != nil {
			log.Printf("failed to connect to real control port: %v", err)
			return
		}
		defer c.ctrlConn.Close()
	}

	c.proxyAndFilerApp()
}

func ctrlAcceptLoop(cfg *config.Config, l net.Listener) {
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			log.Printf("failed to accept control conn: %v", err)
			return
		}

		c := newCtrlProxyConn(cfg, conn)
		go c.handle()
	}
}

func launchCtrlProxy(cfg *config.Config) error {
	cPath := path.Join(cfg.RuntimeDir(), controlSocket)
	os.Remove(cPath)
	l, err := net.Listen("unix", cPath)
	if err != nil {
		return err
	}

	go ctrlAcceptLoop(cfg, l)

	return nil
}
