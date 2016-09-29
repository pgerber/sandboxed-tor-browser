// manifest.go - On disk manifest.
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
	"os"
	"path"

	"github.com/BurntSushi/toml"

	"cmd/sandboxed-tor-browser/internal/config"
)

const (
	manifestFile = "manifest.toml"
)

type manifest struct {
	Channel      string
	Architecture string
	Locale       string

	Version string
}

func (m *manifest) Write(cfg *config.Config) error {
	fpath := path.Join(cfg.UserDataDir(), manifestFile)

	f, err := os.OpenFile(fpath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	e := toml.NewEncoder(f)
	return e.Encode(m)
}

func loadManifest(cfg *config.Config) (*manifest, error) {
	fpath := path.Join(cfg.UserDataDir(), manifestFile)
	if _, err := os.Stat(fpath); err == nil {
		m := new(manifest)
		if _, err = toml.DecodeFile(fpath, m); err != nil {
			return nil, err
		}

		return m, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return nil, nil
}
