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
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"syscall"

	seccomp "github.com/seccomp/libseccomp-golang"

	"cmd/sandboxed-tor-browser/internal/data"
)

func installTorBrowserSeccompProfile(fd *os.File) error {
	rules, err := data.Asset("torbrowser-launcher-whitelist.seccomp")
	if err != nil {
		fd.Close()
		return err
	}

	var extraRules []byte
	if runtime.GOARCH == "386" {
		extraRules, err = data.Asset("torbrowser-launcher-whitelist-extras-i386.seccomp")
		if err != nil {
			fd.Close()
			return err
		}
	}

	log.Printf("seccomp: Using Tor Browser profile.")

	return installOzSeccompProfile(fd, rules, extraRules, false)
}

func installTorSeccompProfile(fd *os.File) error {
	rules, err := data.Asset("tor-whitelist.seccomp")
	if err != nil {
		fd.Close()
		return err
	}

	var extraRules []byte
	if runtime.GOARCH == "386" {
		extraRules, err = data.Asset("tor-whitelist-extras-i386.seccomp")
		if err != nil {
			fd.Close()
			return err
		}
	}

	log.Printf("seccomp: Using Tor profile.")

	return installOzSeccompProfile(fd, rules, extraRules, false)
}

func installBasicSeccompBlacklist(fd *os.File) error {
	rules, err := data.Asset("blacklist.seccomp")
	if err != nil {
		fd.Close()
		return err
	}

	log.Printf("seccomp: Using blacklist.")

	return installOzSeccompProfile(fd, rules, nil, true)
}

func installOzSeccompProfile(fd *os.File, rules []byte, extraRules []byte, isBlacklist bool) error {
	const ENOSYS = 38

	if extraRules != nil {
		rules = append(rules, '\n')
		rules = append(rules, extraRules...)
		rules = append(rules, '\n')
	}

	defer fd.Close()

	var defaultAct, ruleAct seccomp.ScmpAction
	if isBlacklist {
		defaultAct = seccomp.ActAllow
		ruleAct = seccomp.ActErrno.SetReturnCode(ENOSYS)
	} else {
		defaultAct = seccomp.ActErrno.SetReturnCode(ENOSYS)
		ruleAct = seccomp.ActAllow
	}

	f, err := seccomp.NewFilter(defaultAct)
	if err != nil {
		return err
	}
	defer f.Release()
	if err := f.AddArch(seccomp.ArchNative); err != nil {
		return err
	}

	constantTable := map[string]uint64{
		"PR_SET_NAME":       syscall.PR_SET_NAME,
		"PR_GET_NAME":       syscall.PR_GET_NAME,
		"PR_GET_TIMERSLACK": syscall.PR_GET_TIMERSLACK,
		"PR_SET_SECCOMP":    syscall.PR_SET_SECCOMP,
		"PR_SET_DUMPABLE":   syscall.PR_SET_DUMPABLE,
		"PR_SET_PDEATHSIG":  syscall.PR_SET_PDEATHSIG,
		"AF_UNIX":           syscall.AF_UNIX,
		"AF_INET":           syscall.AF_INET,
		"AF_INET6":          syscall.AF_INET6,
		"AF_NETLINK":        syscall.AF_NETLINK,

		"EPOLL_CTL_ADD": syscall.EPOLL_CTL_ADD,
		"EPOLL_CTL_MOD": syscall.EPOLL_CTL_MOD,
		"EPOLL_CTL_DEL": syscall.EPOLL_CTL_DEL,

		"PROT_READ": syscall.PROT_READ,
		"PROT_NONE": syscall.PROT_NONE,

		"LOCK_EX_NB": syscall.LOCK_EX | syscall.LOCK_NB,
		"LOCK_UN":    syscall.LOCK_UN,
	}

	// Only certain architectures, and sufficiently new libseccomp
	// supports conditionals.
	canUseConditionals := runtime.GOARCH == "amd64" && libseccompAtLeast(2, 2, 1)
	if !canUseConditionals {
		log.Printf("seccomp: Either libseccomp or the current arch does not support conditionals.")
	}

	// Parse the rule set and build seccomp rules.
	for ln, l := range bytes.Split(rules, []byte{'\n'}) {
		l = bytes.TrimSpace(l)
		if len(l) == 0 { // Empty line.
			continue
		}
		if idx := bytes.IndexRune(l, '#'); idx != -1 { // Hnadle Comments.
			if idx == 0 {
				continue
			}
			l = bytes.TrimSpace(l[0:idx])
			if len(l) == 0 {
				continue
			}
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
				// Continue instead of failing on ENOSYS.  It's a whitelist.
				// the application will either do without the call, or fail
				// horribly.
				log.Printf("seccomp: unknown system call: %v", scallName)
				continue
			}

			rawCond := bytes.TrimSpace(sp[1])
			if !canUseConditionals || bytes.Equal(rawCond, []byte{'1'}) {
				if err = f.AddRule(scall, ruleAct); err != nil {
					return err
				}
			} else {
				argConds := make([][]uint64, 5)
				conds := bytes.Split(rawCond, []byte{'|', '|'})
				if len(conds) < 1 {
					return fmt.Errorf("seccomp: invalid rule: %d:%v", ln, string(l))
				}
				for _, v := range conds {
					v = bytes.TrimSpace(v)
					spCond := bytes.Split(v, []byte{'=', '='})
					if len(spCond) != 2 {
						return fmt.Errorf("seccomp: invalid condition: %d:%v", ln, string(l))
					}

					arg := bytes.TrimSpace(spCond[0])
					argN, err := strconv.Atoi(string(bytes.TrimPrefix(arg, []byte{'a', 'r', 'g'})))
					if err != nil {
						return fmt.Errorf("seccomp: invalid argument: %d:%v", ln, string(l))
					}
					if argN < 0 || argN > 5 {
						return fmt.Errorf("seccomp: invalid argument reg: %d:%v", ln, string(l))
					}

					rawVal := string(bytes.TrimSpace(spCond[1]))
					val, ok := constantTable[rawVal]
					if !ok {
						val, err = strconv.ParseUint(rawVal, 0, 64)
						if err != nil {
							return fmt.Errorf("seccomp: invalid value: %d:%v: %v", ln, string(l), err)
						}
					}

					argConds[argN] = append(argConds[argN], val)
				}

				var scConds []seccomp.ScmpCondition
				for arg, vals := range argConds {
					if len(vals) == 0 {
						continue
					}
					for _, val := range vals {
						cond, err := seccomp.MakeCondition(uint(arg), seccomp.CompareEqual, val)
						if err != nil {
							return err
						}
						scConds = append(scConds, cond)
					}
				}

				if err = f.AddRuleConditionalExact(scall, ruleAct, scConds); err != nil {
					return err
				}
			}
		} else if bytes.IndexByte(l, '=') != -1 {
			// Declaration.
			sp := bytes.Split(l, []byte{'='})
			if len(sp) != 2 {
				return fmt.Errorf("seccomp: invalid constant: %d:%v", ln, string(l))
			}
			k := string(bytes.TrimSpace(sp[0]))
			v, err := strconv.ParseUint(string(bytes.TrimSpace(sp[1])), 0, 64)
			if err != nil {
				return fmt.Errorf("seccomp: invalid conditional: %d:%v: %v", ln, string(l), err)
			}
			constantTable[k] = v
		} else {
			return fmt.Errorf("seccomp: syntax error in profile: %d:%v", ln, string(l))
		}
	}

	return f.ExportBPF(fd)
}

func libseccompAtLeast(maj, min, micro int) bool {
	iMaj, iMin, iMicro := seccomp.GetLibraryVersion()
	if iMaj > maj {
		return true
	}
	if iMaj == maj && iMin > min {
		return true
	}
	if iMaj == maj && iMin == min && iMicro >= micro {
		return true
	}
	return false
}
