// version.go - Upstream version checker.
// Copyright (C) 2016  Yawning Angel.
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/.

package installer

import (
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
		downloadsBase = "https://dist.torproject.org/torbrowser/update_2/"
		downloadsTail = "/downloads.json"
	)
	url := downloadsBase + cfg.Channel + downloadsTail

	// Fetch the json document containing the current release.
	response, err := orhttp.Get(ctrl, url, distTpoCertChain)
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
