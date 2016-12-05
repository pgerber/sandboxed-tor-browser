// secomp.go - Sandbox seccomp rules.
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

package sandbox

import (
	"os"
	"runtime"

	"cmd/sandboxed-tor-browser/internal/data"
)

func installTorSeccompProfile(fd *os.File, useBridges bool) error {
	assetFile := "tor-"
	if useBridges {
		assetFile = assetFile + "obfs4-"
	}
	assetFile = assetFile + runtime.GOARCH + ".bpf"

	bpf, err := data.Asset(assetFile)
	if err != nil {
		return err
	}

	return writeBuffer(fd, bpf)
}

func installTorBrowserSeccompProfile(fd *os.File) error {
	assetFile := "torbrowser-" + runtime.GOARCH + ".bpf"

	bpf, err := data.Asset(assetFile)
	if err != nil {
		return err
	}

	return writeBuffer(fd, bpf)
}
