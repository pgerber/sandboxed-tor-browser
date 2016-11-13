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

	seccomp "github.com/seccomp/libseccomp-golang"
)

func installBasicBlacklist(fd *os.File) error {
	defer fd.Close()

	f, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return err
	}
	defer f.Release()
	if err := f.AddArch(seccomp.ArchNative); err != nil {
		return err
	}

	// Install a basic blacklist of calls that should essentially never be
	// allowed, due to potential security/privacy issues.  Processes that
	// require more, should use a whitelist instead.
	actEPerm := seccomp.ActErrno.SetReturnCode(1)
	syscallBlacklist := []string{
		// linux-user-chroot (v0 profile)
		"syslog",      // Block dmesg
		"uselib",      // Useless old syscall
		"personality", // Don't allow you to switch to bsd emulation or whatnot
		"acct",        // Don't allow disabling accounting
		"modify_ldt",  // 16-bit code is unnecessary in the sandbox, and modify_ldt is a historic source of interesting information leaks.
		"quotactl",    // Don't allow reading current quota use

		// Scary VM/NUMA ops:
		"move_pages",
		"mbind",
		"get_mempolicy",
		"set_mempolicy",
		"migrate_pages",

		// Don't allow subnamespace setups:
		// XXX/yawning: The clone restriction breaks bwrap.  c'est la vie.  It
		// looks like Mozilla is considering using user namespaces for the
		// content process sandboxing efforts, so this may need to be enabled.
		"unshare",
		"mount",
		"pivot_root",
		// {SCMP_SYS(clone), &SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)}, // Breaks bwrap.

		// Profiling operations; we expect these to be done by tools from
		// outside the sandbox.  In particular perf has been the source of many
		// CVEs.
		"perf_event_open",
		"ptrace",

		// firejail seccomp_filter_64()
		// mount
		"umount2",
		"kexec_load",
		// ptrace
		"open_by_handle_at",
		"name_to_handle_at",
		"create_module",
		"init_module",
		"finit_module",
		"delete_module",
		"iopl",
		"ioperm",
		"ioprio_set",
		"swapon",
		"swapoff",
		// syslog
		"process_vm_readv",
		"process_vm_writev",
		"sysfs",
		"_sysctl",
		"adjtimex",
		"clock_adjtime",
		"lookup_dcookie",
		// perf_event_open
		"fanotify_init",
		"kcmp",
		"add_key",
		"request_key",
		"keyctl",
		// uselib
		// acct
		// modify_ldt
		// pivot_root
		"io_setup",
		"io_destroy",
		"io_getevents",
		"io_submit",
		"io_cancel",
		"remap_file_pages",
		// mbind
		// get_mempolicy
		// set_mempolicy
		// migrate_pages
		// move_pages
		"vmsplice",
		"chroot",
		"tuxcall",
		"reboot",
		"nfsservctl",
		"get_kernel_syms",
	}
	if runtime.GOARCH == "386" {
		syscallBlacklist = append(syscallBlacklist, "vm86", "vm86old")
	}

	for _, n := range syscallBlacklist {
		s, err := seccomp.GetSyscallFromName(n)
		if err != nil {
			return err
		}
		if err := f.AddRule(s, actEPerm); err != nil {
			return err
		}
	}

	// Compile the filter rules, and write it out to the bwrap child process.
	return f.ExportBPF(fd)
}
