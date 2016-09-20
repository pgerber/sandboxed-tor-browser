// orhttp.go - Torified HTTP downloader.
// Copyright (C) 2016  Yawning Angel.
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/.

// Package orhttp implements a HTTP client that dispatches requests over Tor.
package orhttp

import (
	"crypto/x509"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	gourl "net/url"
	"os"
	"strconv"

	"git.schwanenlied.me/yawning/bulb.git"
	"golang.org/x/net/proxy"
)

var emptyTLSNextProtoMap map[string]func(string, *tls.Conn)http.RoundTripper

// Get issues a HTTP request over Tor, using the socks port returned from ctrl,
// optionally validating the peer's TLS certificate chain.
func Get(ctrl *bulb.Conn, url string, certChain []*x509.Certificate) (*http.Response, error) {
	// Derive the stream isolation tag.
	auth, err := proxyAuthFromURL(url)
	if err != nil {
		return nil, err
	}

	// Create the SOCKS dialer, querying the control port for proxy.
	torDialer, err := ctrl.Dialer(auth)
	if err != nil {
		return nil, err
	}

	// Create the HTTP client instance, with disabled HTTP/2 support,
	// that does not follow redirects.
	client := &http.Client{
		Transport: &http.Transport{
			Dial: torDialer.Dial,
			TLSNextProto: emptyTLSNextProtoMap,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("received a redirect via: %v", via[0].URL)
		},
	}

	// Create a HTTP request.
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "") // Don't send a User-Agent header.

	// Dispatch the GET request.
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// If the caller supplied a cert chain, ensure it matches the one provided
	// by the peer.
	if certChain != nil && !certChainEquals(certChain, resp.TLS.PeerCertificates) {
		resp.Body.Close()
		return nil, errors.New("certificate chain mismatch")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http status: %v", resp.StatusCode)
	}

	return resp, nil
}

func proxyAuthFromURL(url string) (*proxy.Auth, error) {
	parsed, err := gourl.Parse(url)
	if err != nil {
		return nil, err
	}

	return &proxy.Auth{
		User:     parsed.Host,
		Password: "sandboxed-tor-browser:" + strconv.Itoa(os.Getpid()),
	}, nil
}

func certChainEquals(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	for i, aCert := range a {
		if !aCert.Equal(b[i]) {
			return false
		}
	}

	return true
}

func init() {
	// Per the HTTP package documentation the correct way to disable HTTP/2
	// support is to set TLSNextProto to an empty map.
	emptyTLSNextProtoMap = make(map[string]func(string, *tls.Conn)http.RoundTripper)
}
