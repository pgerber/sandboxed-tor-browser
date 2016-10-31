//  metadata.go - Tor Browser install/update metadata routines.
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

// Package installer contains routines used for installing and or updating Tor
// Browser.
package installer

import (
	"encoding/json"
	"fmt"

	"cmd/sandboxed-tor-browser/internal/data"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

type installURLs struct {
	DownloadsURLs map[string]string
	UpdateURLBase string
}

var urls *installURLs

type downloads struct {
	Version   string
	Downloads map[string]downloadsArchEntry
}

type downloadsArchEntry map[string]*DownloadsEntry

// DownloadsEntry is a bundle download entry.
type DownloadsEntry struct {
	// Sig is the URL to the PGP signature of the Binary.
	Sig string

	// Binary is the URL to the tar.xz bundle.
	Binary string
}

// DownloadsURL returns the `downloads.json` URL for the configured channel.
func DownloadsURL(cfg *config.Config) string {
	return urls.DownloadsURLs[cfg.Channel]
}

// GetDownloadsEntry parses the json file and returns the Version and
// appropriate DownloadsEntry for the current configuration.
func GetDownloadsEntry(cfg *config.Config, b []byte) (string, *DownloadsEntry, error) {
	d := &downloads{}
	if err := json.Unmarshal(b, &d); err != nil {
		return "", nil, err
	}
	if a := d.Downloads[cfg.Architecture]; a == nil {
		return "", nil, fmt.Errorf("no downloads for architecture: %v", cfg.Architecture)
	} else if e := a[cfg.Locale]; e == nil {
		return "", nil, fmt.Errorf("no downloads for locale: %v", cfg.Locale)
	} else {
		return d.Version, e, nil
	}
}

func init() {
	urls = new(installURLs)
	if b, err := data.Asset("installer/urls.json"); err != nil {
		panic(err)
	} else if err = json.Unmarshal(b, &urls); err != nil {
		panic(err)
	}

}
