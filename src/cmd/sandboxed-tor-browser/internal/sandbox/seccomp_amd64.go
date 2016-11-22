// secomp_amd64.go - Sandbox seccomp rules (amd64).
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

// +build amd64

package sandbox

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/twtiger/gosecco"
	"github.com/twtiger/gosecco/parser"

	"cmd/sandboxed-tor-browser/internal/data"
)

const (
	actAllow  = "allow"
	actKill   = "kill"
	actENOSYS = "ENOSYS"
)

var whitelistSettings = &gosecco.SeccompSettings{
	DefaultPositiveAction: actAllow,
	DefaultNegativeAction: actENOSYS,
	DefaultPolicyAction:   actENOSYS,
	ActionOnX32:           actKill,
	ActionOnAuditFailure:  actKill,
}

var blacklistSettings = &gosecco.SeccompSettings{
	DefaultPositiveAction: actENOSYS,
	DefaultNegativeAction: actAllow,
	DefaultPolicyAction:   actAllow,
	ActionOnX32:           actKill,
	ActionOnAuditFailure:  actKill,
}

var torBrowserSeccompAssets = []string{torBrowserWhitelist}
var torSeccompAssets = []string{torWhitelist}
var blacklistSeccompAssets = []string{basicBlacklist}

func installSeccomp(fd *os.File, assets []string, isBlacklist bool) error {
	defer fd.Close()

	settings := whitelistSettings
	if isBlacklist {
		settings = blacklistSettings
	}

	if len(assets) != 1 {
		return fmt.Errorf("seccomp: asset vector length > 1: %d", len(assets))
	}

	rules, err := data.Asset(assets[0])
	if err != nil {
		return err
	}
	source := &parser.StringSource{
		Name:    assets[0],
		Content: string(rules),
	}

	bpf, err := gosecco.PrepareSource(source, *settings)
	if err != nil {
		return err
	}

	return writeBpf(fd, bpf)
}

func writeBpf(fd *os.File, bpf []unix.SockFilter) error {
	if size, limit := len(bpf), 0xffff; size > limit {
		return fmt.Errorf("filter program too big: %d bpf instructions (limit = %d)", size, limit)
	}

	for _, rule := range bpf {
		if err := binary.Write(fd, binary.LittleEndian, rule); err != nil {
			return err
		}
	}

	return nil
}
