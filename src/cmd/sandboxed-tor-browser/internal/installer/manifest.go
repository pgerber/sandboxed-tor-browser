// manifest.go - On disk manifest.
// Copyright (C) 2016  Yawning Angel.
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/.

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
