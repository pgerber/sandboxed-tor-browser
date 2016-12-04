// secomp_386.go - Sandbox seccomp rules (i386).
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

// +build 386

package sandbox

import (
	"bytes"
	"fmt"
	"log"
	"os"

	seccomp "github.com/seccomp/libseccomp-golang"

	"cmd/sandboxed-tor-browser/internal/data"
)

const (
	torBrowserExtraWhitelist = "torbrowser-launcher-whitelist-extras-i386.seccomp"
	torExtraWhitelist        = "tor-whitelist-extras-i386.seccomp"
	basicExtraBlacklist      = "blacklist-extras-i386.seccomp"
)

var torBrowserSeccompAssets = []string{torBrowserWhitelist, torBrowserExtraWhitelist}
var torSeccompAssets = []string{torWhitelist, torExtraWhitelist}
var torObfs4SeccompAssets = []string{torObfs4Whitelist, torExtraWhitelist}
var blacklistSeccompAssets = []string{basicBlacklist, basicExtraBlacklist}

// installSeccomp on i386 implements a minimal subset of the gosecco
// description launguage sufficient to enumerate system calls listed in
// rule files.
//
// When i386 gains support for filtering system call arguments via seccomp,
// this will need to be beefed up, but hopefully gosecco will be updated
// by then.
func installSeccomp(fd *os.File, assets []string, isBlacklist bool) error {
	defer fd.Close()

	var rules []byte
	for _, asset := range assets {
		b, err := data.Asset(asset)
		if err != nil {
			return err
		}
		rules = append(rules, b...)
		rules = append(rules, '\n')
	}

	actENOSYS := seccomp.ActErrno.SetReturnCode(38)
	defaultAct, ruleAct := actENOSYS, seccomp.ActAllow
	if isBlacklist {
		defaultAct, ruleAct = ruleAct, defaultAct
	}

	f, err := seccomp.NewFilter(defaultAct)
	if err != nil {
		return err
	}
	defer f.Release()
	if err := f.AddArch(seccomp.ArchNative); err != nil {
		return err
	}

	// Parse the rule set and build seccomp rules.
	for ln, l := range bytes.Split(rules, []byte{'\n'}) {
		l = bytes.TrimSpace(l)
		if len(l) == 0 { // Empty line.
			continue
		}
		if idx := bytes.IndexRune(l, '#'); idx == 0 {
			continue
		}

		if bytes.IndexByte(l, ':') != -1 {
			// Rule
			sp := bytes.SplitN(l, []byte{':'}, 2)
			if len(sp) != 2 {
				return fmt.Errorf("seccomp: invalid rule: %d:%v", ln, string(l))
			}

			scallName := string(bytes.TrimSpace(sp[0]))
			scall, err := seccomp.GetSyscallFromName(scallName)
			if err != nil {
				if scallName == "newselect" {
					// The library doesn't have "NR_newselect" yet.
					scall = seccomp.ScmpSyscall(142)
				} else {
					// Continue instead of failing on ENOSYS.  gosecco will fail
					// here, but this allows whitelists to be more futureproof,
					// and handles thing like Debian prehistoric^wstable missing
					// system calls that we would like to allow like `getrandom`.
					log.Printf("seccomp: unknown system call: %v", scallName)
					continue
				}
			}

			// If the system call is present, just add it.  This is x86,
			// seccomp can't filter args on this architecture.
			if err = f.AddRule(scall, ruleAct); err != nil {
				return err
			}
		} else if bytes.IndexByte(l, '=') != -1 {
			// Skip declarations.
			continue
		} else {
			return fmt.Errorf("seccomp: syntax error in profile: %d:%v", ln, string(l))
		}
	}

	return f.ExportBPF(fd)
}
