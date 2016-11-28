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

import "os"

const (
	torBrowserWhitelist = "torbrowser-launcher-whitelist.seccomp"
	torWhitelist        = "tor-whitelist.seccomp"
	torObfs4Whitelist   = "tor-obfs4-whitelist.seccomp"
	basicBlacklist      = "blacklist.seccomp"
)

func installTorBrowserSeccompProfile(fd *os.File) error {
	return installSeccomp(fd, torBrowserSeccompAssets, false)
}

func installTorSeccompProfile(fd *os.File, useBridges bool) error {
	assets := torSeccompAssets
	if useBridges {
		assets = torObfs4SeccompAssets
	}

	return installSeccomp(fd, assets, false)
}

func installBasicSeccompBlacklist(fd *os.File) error {
	return installSeccomp(fd, blacklistSeccompAssets, true)
}
