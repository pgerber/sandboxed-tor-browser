// client.go - SOCSK5 client implementation.
// Copyright (C) 2015, 2016  Yawning Angel.
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/.

package socks5

import (
	"net"

	"golang.org/x/net/proxy"
)

// Redispatch dials the provided proxy and redispatches an existing request.
func Redispatch(proxyNet, proxyAddr string, req *Request) (net.Conn, error) {
	if req.Cmd != CommandConnect {
		return nil, clientError(ReplyCommandNotSupported)
	}

	var auth *proxy.Auth
	if req.Auth.Uname != nil {
		auth = &proxy.Auth{
			User:     string(req.Auth.Uname),
			Password: string(req.Auth.Passwd),
		}
	}
	d, err := proxy.SOCKS5(proxyNet, proxyAddr, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}

	return d.Dial("tcp", req.Addr.String())
}
