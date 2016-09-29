// version.go - Upstream version checker.
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
	// This is subject to change to `aus1.torproject.org` once the cert pinning
	// mess is sorted out.
	//
	// See: https://trac.torproject.org/projects/tor/ticket/19481
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
