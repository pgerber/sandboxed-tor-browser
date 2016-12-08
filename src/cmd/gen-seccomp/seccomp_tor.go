// secomp_tor.go - Sandbox tor seccomp rules.
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

var maskedCloexecNonblock = ^(uint64(syscall.SOCK_CLOEXEC | syscall.SOCK_NONBLOCK))

func compileTorSeccompProfile(fd *os.File, useBridges bool, is386 bool) error {
	defer fd.Close()

	f, err := newWhitelist(is386)
	if err != nil {
		return err
	}
	defer f.Release()

	allowedNoArgs := []string{
		"access",
		"brk",
		"clock_gettime",
		"close",
		"clone",
		"epoll_create",
		"epoll_wait",
		"eventfd2",
		"pipe2",
		"pipe",
		"fstat",
		"getdents",
		"getdents64",
		"getegid",
		"geteuid",
		"getgid",
		"getrlimit",
		"gettimeofday",
		"gettid",
		"getuid",
		"lseek",
		"mkdir",
		"munmap",
		"prlimit64",
		"read",
		"rt_sigreturn",
		"sched_getaffinity",
		"sched_yield",
		"sendmsg",
		"set_robust_list",
		"setrlimit",
		"sigaltstack",
		"stat",
		"uname",
		"wait4",
		"write",
		"writev",
		"exit_group",
		"exit",
		"getrandom",
		"sysinfo",
		"bind",
		"listen",
		"connect",
		"getsockname",
		"recvmsg",
		"recvfrom",
		"sendto",
		"unlink",

		// Calls that tor can filter, but I can't due to not being in
		// the tor daemon's process space.
		"chown",
		"chmod",
		"open",
		"openat",
		"rename",

		// Calls made prior to tor's UseSeccomp being installed.
		"arch_prctl",
		"chdir",
		"execve",
		"getpid",
		"kill",
		"restart_syscall",
		"set_tid_address",
		"unshare",
		"rt_sigaction", // Tor filters this but libc does more.
	}
	if is386 {
		allowedNoArgs386 := []string{
			"fstat64",
			"getegid32",
			"geteuid32",
			"getgid32",
			"getuid32",
			"_llseek",
			"sigreturn",

			"recv",
			"send",
			"stat64",

			"ugetrlimit",
			"set_thread_area",
		}
		allowedNoArgs = append(allowedNoArgs, allowedNoArgs386...)
	}
	if err = allowSyscalls(f, allowedNoArgs, is386); err != nil {
		return err
	}
	if is386 {
		// Handle socketcall() before filtering other things.
		if err = torFilterSocketcall(f, useBridges); err != nil {
			return err
		}
	}

	if err = allowCmpEq(f, "time", 0, 0); err != nil {
		return err
	}
	if err = allowCmpEq(f, "madvise", 2, madvFree); err != nil {
		return err
	}
	if err = allowCmpEq(f, "umask", 0, 022); err != nil {
		return err
	}
	if err = allowCmpEq(f, "rt_sigprocmask", 0, sigBlock, sigSetmask); err != nil {
		return err
	}
	if err = allowCmpEq(f, "epoll_ctl", 1, syscall.EPOLL_CTL_ADD, syscall.EPOLL_CTL_MOD, syscall.EPOLL_CTL_DEL); err != nil {
		return err
	}
	if err = torFilterPrctl(f); err != nil {
		return err
	}
	if err = allowCmpEq(f, "mprotect", 2, syscall.PROT_READ, syscall.PROT_NONE); err != nil {
		return err
	}
	if err = allowCmpEq(f, "flock", 1, syscall.LOCK_EX|syscall.LOCK_NB, syscall.LOCK_UN); err != nil {
		return err
	}
	if err = allowCmpEq(f, "futex", 1, futexWaitBitsetPrivate|futexClockRealtime, futexWaitPrivate, futexWakePrivate); err != nil {
		return err
	}
	if err = allowCmpEq(f, "mremap", 3, mremapMaymove); err != nil {
		return err
	}
	if err = torFilterAccept4(f); err != nil {
		return err
	}
	if err = torFilterPoll(f); err != nil {
		return err
	}
	if err = torFilterSocket(f); err != nil {
		return err
	}
	if err = torFilterSetsockopt(f); err != nil {
		return err
	}
	if err = torFilterGetsockopt(f); err != nil {
		return err
	}
	if err = torFilterSocketpair(f); err != nil {
		return err
	}
	if err = torFilterMmap(f, is386); err != nil {
		return err
	}
	if err = torFilterFcntl(f, is386); err != nil {
		return err
	}

	if useBridges {
		// XXX: One day, all the PTs will live in their own containers.
		//
		// Till then, just whitelist the extra calls obfs4proxy needs.
		obfsCalls := []string{
			"mincore",
			"dup2",
			"select",
			"mkdirat",
			"fsync",
			"getpeername",
			"getppid",
		}
		if is386 {
			obfsCalls = append(obfsCalls, "_newselect")
		}
		if err = allowSyscalls(f, obfsCalls, is386); err != nil {
			return err
		}

		// `mmap` -> `arg2 == PROT_NONE && (arg3 == MAP_PRIVATE|MAP_ANONYMOUS || arg3 == MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS)`
		if err = allowCmpEq(f, "epoll_create1", 0, syscall.EPOLL_CLOEXEC); err != nil {
			return err
		}
		if err = allowCmpEq(f, "mprotect", 2, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
			return err
		}
		if err = allowCmpEq(f, "futex", 1, futexWake, futexWait); err != nil {
			return err
		}
		if err = obfsFilterSetsockopt(f); err != nil {
			return err
		}
		if err = obfsFilterMmap(f, is386); err != nil {
			return err
		}
	}

	return f.ExportBPF(fd)
}

func torFilterSocketcall(f *seccomp.ScmpFilter, useBridges bool) error {
	// This interface needs to die in a fire, because it's leaving
	// gaping attack surface.  It kind of will assuming that things
	// move on to 4.3 or later.
	//
	// Emperically on Fedora 25 getsockopt and setsockopt still are
	// multiplexed, though that may just be my rules or libseccomp2.
	//
	// Re-test after Debian stable moves to a modern kernel.

	allowedCalls := []uint64{
		sysSocket,
		sysBind,
		sysConnect,
		sysListen,
		sysGetsockname,
		sysSocketpair,
		sysSend,
		sysRecv,
		sysSendto,
		sysRecvfrom,
		sysSetsockopt,
		sysGetsockopt,
		sysSendmsg,
		sysRecvmsg,
		sysAccept4,
	}
	if useBridges {
		allowedCalls = append(allowedCalls, sysGetpeername)
	}

	return allowCmpEq(f, "socketcall", 0, allowedCalls...)
}

func torFilterPrctl(f *seccomp.ScmpFilter) error {
	scall, err := seccomp.GetSyscallFromName("prctl")
	if err != nil {
		return err
	}

	isPrSetDumpable, err := seccomp.MakeCondition(0, seccomp.CompareEqual, syscall.PR_SET_DUMPABLE)
	if err != nil {
		return err
	}
	arg1IsZero, err := seccomp.MakeCondition(1, seccomp.CompareEqual, 0)
	if err != nil {
		return err
	}
	if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isPrSetDumpable, arg1IsZero}); err != nil {
		return err
	}

	isPrSetDeathsig, err := seccomp.MakeCondition(0, seccomp.CompareEqual, syscall.PR_SET_PDEATHSIG)
	if err != nil {
		return err
	}
	return f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isPrSetDeathsig})
}

func torFilterAccept4(f *seccomp.ScmpFilter) error {
	scall, err := seccomp.GetSyscallFromName("accept4")
	if err != nil {
		return err
	}

	cond, err := seccomp.MakeCondition(3, seccomp.CompareMaskedEqual, maskedCloexecNonblock, 0)
	if err != nil {
		return nil
	}

	return f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{cond})
}

func torFilterPoll(f *seccomp.ScmpFilter) error {
	scall, err := seccomp.GetSyscallFromName("poll")
	if err != nil {
		return err
	}

	isPollIn, err := seccomp.MakeCondition(1, seccomp.CompareEqual, pollIn)
	if err != nil {
		return err
	}
	timeoutIsTen, err := seccomp.MakeCondition(2, seccomp.CompareEqual, 10)
	if err != nil {
		return err
	}
	return f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isPollIn, timeoutIsTen})
}

func torFilterSocket(f *seccomp.ScmpFilter) error {
	scall, err := seccomp.GetSyscallFromName("socket")
	if err != nil {
		return err
	}

	makeCondType := func(t uint64) (seccomp.ScmpCondition, error) {
		return seccomp.MakeCondition(1, seccomp.CompareMaskedEqual, maskedCloexecNonblock, t)
	}

	// tor allows PF_FILE, which is PF_LOCAL on Linux, not sure why.

	for _, d := range []uint64{syscall.AF_INET, syscall.AF_INET6} {
		isDomain, err := seccomp.MakeCondition(0, seccomp.CompareEqual, d)
		if err != nil {
			return err
		}

		for _, t := range []uint64{syscall.SOCK_STREAM, syscall.SOCK_DGRAM} {
			protocols := []uint64{syscall.IPPROTO_IP, syscall.IPPROTO_UDP}
			if t == syscall.SOCK_STREAM {
				protocols = append(protocols, syscall.IPPROTO_TCP)
			}

			isType, err := makeCondType(t)
			if err != nil {
				return err
			}

			for _, p := range protocols {
				isProtocol, err := seccomp.MakeCondition(2, seccomp.CompareEqual, p)
				if err != nil {
					return err
				}

				if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isDomain, isType, isProtocol}); err != nil {
					return err
				}
			}
		}
	}

	isAfLocal, err := seccomp.MakeCondition(0, seccomp.CompareEqual, syscall.AF_LOCAL)
	if err != nil {
		return err
	}
	for _, t := range []uint64{syscall.SOCK_STREAM, syscall.SOCK_DGRAM} {
		isType, err := makeCondType(t)
		if err != nil {
			return err
		}
		isProtocol, err := seccomp.MakeCondition(2, seccomp.CompareEqual, 0)
		if err != nil {
			return err
		}
		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isAfLocal, isType, isProtocol}); err != nil {
			return err
		}
	}

	// tor allows socket(AF_NETLINK, SOCK_RAW, 0), which is used to check it's
	// IP address, but will take "no".

	return nil
}

func torFilterSetsockopt(f *seccomp.ScmpFilter) error {
	scall, err := seccomp.GetSyscallFromName("setsockopt")
	if err != nil {
		return err
	}

	isSolSocket, err := seccomp.MakeCondition(1, seccomp.CompareEqual, syscall.SOL_SOCKET)
	if err != nil {
		return err
	}

	okOpts := []uint64{
		syscall.SO_REUSEADDR,
		syscall.SO_SNDBUF,
		syscall.SO_RCVBUF,
	}

	for _, opt := range okOpts {
		isOpt, err := seccomp.MakeCondition(2, seccomp.CompareEqual, opt)
		if err != nil {
			return err
		}
		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isSolSocket, isOpt}); err != nil {
			return err
		}
	}

	return nil
}

func torFilterGetsockopt(f *seccomp.ScmpFilter) error {
	scall, err := seccomp.GetSyscallFromName("getsockopt")
	if err != nil {
		return err
	}

	isSolSocket, err := seccomp.MakeCondition(1, seccomp.CompareEqual, syscall.SOL_SOCKET)
	if err != nil {
		return err
	}
	optIsError, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.SO_ERROR)
	if err != nil {
		return err
	}
	return f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isSolSocket, optIsError})
}

func torFilterSocketpair(f *seccomp.ScmpFilter) error {
	scall, err := seccomp.GetSyscallFromName("socketpair")
	if err != nil {
		return err
	}

	isPfLocal, err := seccomp.MakeCondition(0, seccomp.CompareEqual, syscall.AF_LOCAL)
	if err != nil {
		return err
	}

	// XXX: src/common/compat.c:tor_socketpair looks like it uses SOCK_CLOEXEC,
	//  but according to strace, fcntl is used to actually set the flag (6.0.6).
	okTypes := []uint64{
		syscall.SOCK_STREAM,
		syscall.SOCK_STREAM | syscall.SOCK_CLOEXEC,
	}
	for _, t := range okTypes {
		isType, err := seccomp.MakeCondition(1, seccomp.CompareEqual, t)
		if err != nil {
			return err
		}
		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isPfLocal, isType}); err != nil {
			return err
		}
	}
	return nil
}

func torFilterMmap(f *seccomp.ScmpFilter, is386 bool) error {
	scallMmap, err := seccomp.GetSyscallFromName("mmap")
	if err != nil {
		return err
	}
	scalls := []seccomp.ScmpSyscall{scallMmap}
	if is386 {
		scallMmap2, err := seccomp.GetSyscallFromName("mmap2")
		if err != nil {
			return err
		}
		scalls = append(scalls, scallMmap2)
	}

	// (arg2 == PROT_READ && arg3 == MAP_PRIVATE)
	isProtRead, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.PROT_READ)
	if err != nil {
		return err
	}
	isPrivate, err := seccomp.MakeCondition(3, seccomp.CompareEqual, syscall.MAP_PRIVATE)
	if err != nil {
		return err
	}
	for _, scall := range scalls {
		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isProtRead, isPrivate}); err != nil {
			return err
		}
	}

	// (arg2 == PROT_NONE && arg3 == MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE)
	isProtNone, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.PROT_NONE)
	if err != nil {
		return err
	}
	isProtNoneFlags, err := seccomp.MakeCondition(3, seccomp.CompareEqual, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_NORESERVE)
	if err != nil {
		return err
	}
	for _, scall := range scalls {
		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isProtNone, isProtNoneFlags}); err != nil {
			return err
		}
	}

	isProtReadWrite, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.PROT_READ|syscall.PROT_WRITE)
	if err != nil {
		return err
	}
	rwFlags := []uint64{
		syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS,
		syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | syscall.MAP_STACK,
		syscall.MAP_PRIVATE | syscall.MAP_FIXED | syscall.MAP_DENYWRITE,
		syscall.MAP_PRIVATE | syscall.MAP_FIXED | syscall.MAP_ANONYMOUS,
		syscall.MAP_PRIVATE | syscall.MAP_DENYWRITE,
	}
	for _, flag := range rwFlags {
		isFlag, err := seccomp.MakeCondition(3, seccomp.CompareEqual, flag)
		if err != nil {
			return err
		}
		for _, scall := range scalls {
			if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isProtReadWrite, isFlag}); err != nil {
				return err
			}
		}
	}

	//  (arg2 == PROT_READ | PROT_EXEC && arg3 == MAP_PRIVATE | MAP_DENYWRITE)
	// This is needed for ld-linux.so.
	isProtReadExec, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.PROT_READ|syscall.PROT_EXEC)
	if err != nil {
		return err
	}
	isProtReadExecFlags, err := seccomp.MakeCondition(3, seccomp.CompareEqual, syscall.MAP_PRIVATE|syscall.MAP_DENYWRITE)
	if err != nil {
		return err
	}
	for _, scall := range scalls {
		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isProtReadExec, isProtReadExecFlags}); err != nil {
			return err
		}
	}

	return nil
}

func torFilterFcntl(f *seccomp.ScmpFilter, is386 bool) error {
	scallFcntl, err := seccomp.GetSyscallFromName("fcntl")
	if err != nil {
		return err
	}
	scalls := []seccomp.ScmpSyscall{scallFcntl}
	if is386 {
		scallFcntl64, err := seccomp.GetSyscallFromName("fcntl64")
		if err != nil {
			return err
		}
		scalls = append(scalls, scallFcntl64)
	}

	isFGetfl, err := seccomp.MakeCondition(1, seccomp.CompareEqual, syscall.F_GETFL)
	if err != nil {
		return err
	}
	isFGetfd, err := seccomp.MakeCondition(1, seccomp.CompareEqual, syscall.F_GETFD)
	if err != nil {
		return err
	}

	isFSetfl, err := seccomp.MakeCondition(1, seccomp.CompareEqual, syscall.F_SETFL)
	if err != nil {
		return err
	}
	isFSetflFlags, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.O_RDWR|syscall.O_NONBLOCK)
	if err != nil {
		return err
	}

	isFSetfd, err := seccomp.MakeCondition(1, seccomp.CompareEqual, syscall.F_SETFD)
	if err != nil {
		return err
	}
	isFdCloexec, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.FD_CLOEXEC)
	if err != nil {
		return err
	}

	for _, scall := range scalls {
		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isFGetfl}); err != nil {
			return err
		}
		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isFGetfd}); err != nil {
			return err
		}

		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isFSetfl, isFSetflFlags}); err != nil {
			return err
		}

		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isFSetfd, isFdCloexec}); err != nil {
			return err
		}
	}

	return nil
}

func obfsFilterSetsockopt(f *seccomp.ScmpFilter) error {
	scall, err := seccomp.GetSyscallFromName("setsockopt")
	if err != nil {
		return err
	}

	isSolTcp, err := seccomp.MakeCondition(1, seccomp.CompareEqual, syscall.SOL_TCP)
	if err != nil {
		return err
	}
	isTcpNodelay, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.TCP_NODELAY)
	if err != nil {
		return err
	}
	if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isSolTcp, isTcpNodelay}); err != nil {
		return err
	}

	isSolSocket, err := seccomp.MakeCondition(1, seccomp.CompareEqual, syscall.SOL_SOCKET)
	if err != nil {
		return err
	}
	isSoBroadcast, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.SO_BROADCAST)
	if err != nil {
		return err
	}
	if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isSolSocket, isSoBroadcast}); err != nil {
		return err
	}

	isSolIpv6, err := seccomp.MakeCondition(1, seccomp.CompareEqual, syscall.SOL_IPV6)
	if err != nil {
		return err
	}
	isIpv6Only, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.IPV6_V6ONLY)
	if err != nil {
		return err
	}
	if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isSolIpv6, isIpv6Only}); err != nil {
		return err
	}

	return nil
}

// `mmap` -> `arg2 == PROT_NONE && (arg3 == MAP_PRIVATE|MAP_ANONYMOUS || arg3 == MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS)`
func obfsFilterMmap(f *seccomp.ScmpFilter, is386 bool) error {
	scallMmap, err := seccomp.GetSyscallFromName("mmap")
	if err != nil {
		return err
	}
	scalls := []seccomp.ScmpSyscall{scallMmap}
	if is386 {
		scallMmap2, err := seccomp.GetSyscallFromName("mmap2")
		if err != nil {
			return err
		}
		scalls = append(scalls, scallMmap2)
	}

	isProtNone, err := seccomp.MakeCondition(2, seccomp.CompareEqual, syscall.PROT_NONE)
	if err != nil {
		return err
	}
	protNoneFlags := []uint64{
		syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS,
		syscall.MAP_PRIVATE | syscall.MAP_FIXED | syscall.MAP_ANONYMOUS,
	}
	for _, flag := range protNoneFlags {
		isFlag, err := seccomp.MakeCondition(3, seccomp.CompareEqual, flag)
		if err != nil {
			return err
		}
		for _, scall := range scalls {
			if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{isProtNone, isFlag}); err != nil {
				return err
			}
		}
	}
	return nil
}
