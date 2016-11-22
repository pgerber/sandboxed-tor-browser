// manifest.go - Manifest routines.
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

package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"cmd/sandboxed-tor-browser/internal/utils"
)

// Manifest contains the installed Tor Browser information.
type Manifest struct {
	// Version is the installed version.
	Version string `json:"version,omitEmpty"`

	// Architecture is the installed Tor Browser architecture.
	Architecture string `json:"architecture,omitEmpty"`

	// Channel is the installed Tor Browser channel.
	Channel string `json:"channel,omitEmpty"`

	// Locale is the installed Tor Browser locale.
	Locale string `json:"locale,omitEmpty"`

	isDirty bool
	path    string
}

// SetVersion sets the manifest version and marks the config dirty.
func (m *Manifest) SetVersion(v string) {
	if m.Version != v {
		m.isDirty = true
		m.Version = v
	}
}

// Sync flushes the manifest to disk, if the manifest is dirty.
func (m *Manifest) Sync() error {
	if m.isDirty {
		// Encode to JSON and write to disk.
		if b, err := json.Marshal(&m); err != nil {
			return err
		} else if err = ioutil.WriteFile(m.path, b, utils.FileMode); err != nil {
			return err
		}

		m.isDirty = false
	}
	return nil
}

// BundleVersionAtLeast returns true if the bundle version is greater than or
// equal to the specified version.
func (m *Manifest) BundleVersionAtLeast(major, minor int) bool {
	vStr := strings.TrimSuffix(m.Version, "-hardened")
	if m.Version == "" {
		return false
	}
	if m.Channel == "alpha" || m.Channel == "hardened" {
		vStr = strings.Replace(vStr, "a", ".", 1)
	}

	// Split into major/minor/pl.
	v := strings.Split(vStr, ".")
	if len(v) < 2 { // Need at least a major/minor.
		return false
	}

	iMaj, err := strconv.Atoi(v[0])
	if err != nil {
		return false
	}
	iMin, err := strconv.Atoi(v[1])
	if err != nil {
		return false
	}

	// Do the version comparison.
	if iMaj > major {
		return true
	}
	if iMaj == major && iMin >= minor {
		return true
	}
	return false
}

// Purge deletes the manifest.
func (m *Manifest) Purge() {
	os.Remove(m.path)
}

// LoadManifest loads a manifest if present.  Note that a missing manifest is
// not treated as an error.
func LoadManifest(cfg *Config) (*Manifest, error) {
	m := new(Manifest)

	// Load the manifest file.
	if b, err := ioutil.ReadFile(cfg.manifestPath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	} else if err = json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	m.path = cfg.manifestPath
	return m, nil
}

// NewManifest returns a new manifest.
func NewManifest(cfg *Config, version string) *Manifest {
	m := new(Manifest)
	m.Version = version
	m.Architecture = cfg.Architecture
	m.Channel = cfg.Channel
	m.Locale = cfg.Locale

	m.isDirty = true
	m.path = cfg.manifestPath

	return m
}
