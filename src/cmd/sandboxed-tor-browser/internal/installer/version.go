// version.go - Upstream version checker.
// Copyright (C) 2016  Yawning Angel.
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/.

package installer

import (
	"crypto/x509"
	"encoding/json"

	"git.schwanenlied.me/yawning/bulb.git"

	"cmd/sandboxed-tor-browser/internal/config"
	"cmd/sandboxed-tor-browser/internal/orhttp"
)

type parsedDownloads struct {
	Version   string
	Downloads map[string]archEntry
}

type archEntry map[string]*downloadEntry

type downloadEntry struct {
	Sig    string
	Binary string
}

func getBundleDownloads(cfg *config.Config, ctrl *bulb.Conn) (*parsedDownloads, error) {
	const (
		distTpoBase = "https://dist.torproject.org/torbrowser/update_2/"
		aus1TpoBase = "https://aus1.torproject.org/torbrowser/update_2/"

		downloadsTail = "/downloads.json"
	)

	// The autoupdate infrastructure currently is split between dist.tp.o
	// (release) and aus1.tp.o (other channels).  This is set to be unified
	// in the future to aus1.tp.o with a redirect, but frustratingly, the
	// latter uses a Let's Encrypt cert so can't be pinned.
	//
	// https://trac.torproject.org/projects/tor/ticket/19481
	var certChain  []*x509.Certificate
	downloadsBase := aus1TpoBase
	if cfg.Channel == "release" {
		downloadsBase = distTpoBase
		certChain = distTpoCertChain
	}

	url := downloadsBase + cfg.Channel + downloadsTail

	// Fetch the json document containing the current release.
	response, err := orhttp.Get(ctrl, url, certChain)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	downloads := &parsedDownloads{}
	dec := json.NewDecoder(response.Body)
	if err := dec.Decode(&downloads); err != nil {
		return nil, err
	}

	return downloads, nil
}
