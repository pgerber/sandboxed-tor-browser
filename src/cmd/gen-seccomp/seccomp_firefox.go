// secomp_firefox.go - Firefox sandbox seccomp rules.
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

package main

import (
	"os"
	"syscall"

	seccomp "github.com/seccomp/libseccomp-golang"
)

func compileTorBrowserSeccompProfile(fd *os.File, is386 bool) error {
	defer fd.Close()

	f, err := newWhitelist(is386)
	if err != nil {
		return err
	}
	defer f.Release()

	// TODO; Filter the arguments on more of these calls.
	//
	// Maybe draaw inspiration from:
	// https://github.com/mozilla/gecko-dev/blob/master/security/sandbox/linux/SandboxFilter.cpp
	allowedNoArgs := []string{
		"clock_gettime",
		"clock_getres",
		"gettimeofday",
		"nanosleep",
		"sched_yield",

		"open",
		"openat",
		"pread64",
		"read",
		"recvfrom",
		"pwrite64",
		"sendto",
		"write",
		"writev",
		"close",

		"access",
		"creat",
		"chmod",
		"chdir",
		"dup2",
		"dup",
		"fadvise64",
		"fallocate",
		"fcntl",
		"fchmod",
		"fchown",
		"fchdir",
		"fdatasync",
		"fstat",
		"fstatfs",
		"ftruncate",
		"fsync",
		"getcwd",
		"getdents",
		"getdents64",
		"link",
		"lseek",
		"lstat",
		"mkdir",
		"name_to_handle_at",
		"newfstatat",
		"pipe",
		"pipe2",
		"readahead",
		"readlink",
		"readlinkat",
		"rename",
		"rmdir",
		"stat",
		"splice",
		"statfs",
		"symlink",
		"unlink",
		"utime",
		"utimes",

		"accept4",
		"bind",
		"connect",
		"epoll_create",
		"epoll_create1",
		"epoll_ctl",
		"epoll_wait",
		"eventfd2",
		"getsockname",
		"getsockopt",
		"getpeername",
		"listen",
		"poll",
		"ppoll",
		"recvmsg",
		"socketpair",
		"select",
		"sendmsg",
		"setsockopt",
		"shutdown",

		"inotify_add_watch",
		"inotify_init1",
		"inotify_rm_watch",

		"brk",
		"mincore",
		"mmap",
		"mprotect",
		"mremap",
		"munmap",

		"shmdt",
		"shmat",
		"shmctl",
		"shmget",

		"alarm",
		"execve",
		"getrandom",
		"getrlimit",
		"getrusage",
		"getpgrp",
		"getppid",
		"getpid",
		"getpriority",
		"getresgid",
		"getresuid",
		"gettid",
		"getuid",
		"geteuid",
		"getgid",
		"getegid",
		"rt_sigaction",
		"rt_sigprocmask",
		"rt_sigreturn",
		"sigaltstack",

		"arch_prctl",
		"capset",
		"capget",
		"clone",
		"exit",
		"exit_group",
		"kill",
		"restart_syscall",
		"seccomp",
		"sched_getaffinity",
		"sched_setscheduler",
		"setpriority",
		"set_robust_list",
		"setsid",
		"set_tid_address",
		"setresuid",
		"setresgid",
		"sysinfo",
		"tgkill",
		"umask",
		"uname",
		"unshare",
		"wait4",

		// ASAN explodes if this doesn't work.  Sigh.
		"setrlimit",

		// Firefox uses this, but will take no for an answer.
		// "quotactl",

		// Subgraph's profile has these, but that's for Tor Browser Launcher.
		//
		// "vfork",
		// "memfd_create", (PulseAudio?  Won't work in our container.)
		// "personality",
		// "mlock",
	}
	if is386 {
		allowedNoArgs386 := []string{
			"fadvise64_64",
			"fcntl64",
			"fstat64",
			"fstatfs64",
			"ftruncate64",
			"lstat64",
			"stat64",
			"statfs64",
			"_llseek",

			"mmap2",
			"ugetrlimit",
			"set_thread_area",
			"waitpid",

			"getgid32",
			"getuid32",
			"getresgid32",
			"getresuid32",

			"recv",
			"send",
			"_newselect",
		}
		allowedNoArgs = append(allowedNoArgs, allowedNoArgs386...)
	}
	if err = allowSyscalls(f, allowedNoArgs, is386); err != nil {
		return err
	}

	// Like with how I do the tor rules, handle socketcall() before everything
	// else.
	if is386 {
		if err = ffFilterSocketcall(f); err != nil {
			return err
		}

		// Unrelated to sockets, only i386 needs these, and it can be filtered.
		if err = allowCmpEq(f, "time", 0, 0); err != nil {
			return err
		}
		if err = ffFilterPrlimit64(f); err != nil {
			return err
		}
	}

	// Because we patch PulseAudio's mutex creation, we can omit all PI futex
	// calls.
	if err = allowCmpEq(f, "futex", 1, futexWait, futexWaitPrivate, futexWakePrivate, futexCmpRequeuePrivate, futexWakeOpPrivate, futexWaitBitsetPrivate|futexClockRealtime, futexWake, futexWaitBitsetPrivate); err != nil {
		return err
	}

	if err = allowCmpEq(f, "madvise", 2, madvNormal, madvDontneed, madvFree); err != nil {
		return err
	}
	if err = allowCmpEq(f, "ioctl", 1, fionread, tcgets, tiocgpgrp); err != nil {
		return err
	}
	if err = allowCmpEq(f, "prctl", 0, syscall.PR_SET_NAME, syscall.PR_GET_NAME, syscall.PR_GET_TIMERSLACK, syscall.PR_SET_SECCOMP); err != nil {
		return err
	}
	if err = allowCmpEq(f, "socket", 0, syscall.AF_UNIX); err != nil {
		return err
	}

	return f.ExportBPF(fd)
}

func ffFilterSocketcall(f *seccomp.ScmpFilter) error {
	// This is kind of pointless because it allows basically all the things.
	allowedCalls := []uint64{
		sysSocket,
		sysBind,
		sysConnect,
		sysListen,
		sysGetsockname,
		sysGetpeername,
		sysSocketpair,
		sysSend,
		sysRecv,
		sysSendto,
		sysRecvfrom,
		sysShutdown,
		sysSetsockopt,
		sysGetsockopt,
		sysSendmsg,
		sysRecvmsg,
		sysAccept4,
	}
	return allowCmpEq(f, "socketcall", 0, allowedCalls...)
}

func ffFilterPrlimit64(f *seccomp.ScmpFilter) error {
	scall, err := seccomp.GetSyscallFromName("prlimit64")
	if err != nil {
		return err
	}

	// Per Mozilla's sandbox: only prlimit64(0, resource,  NULL, old_limit)
	// which is functionally equivalent to getrlimit().  0 instead of the
	// pid() is a glibc-ism.

	isPid0, err := seccomp.MakeCondition(0, seccomp.CompareEqual, 0)
	if err != nil {
		return err
	}
	isNoNewLimit, err := seccomp.MakeCondition(2, seccomp.CompareEqual, 9)
	if err != nil {
		return err
	}
	return f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isPid0, isNoNewLimit})
}
