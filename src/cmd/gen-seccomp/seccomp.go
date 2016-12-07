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

package main

import (
	"fmt"

	seccomp "github.com/seccomp/libseccomp-golang"
)

const (
	madvNormal    = 0 // MADV_NORMAL
	madvDontneed  = 4 // MADV_DONTNEED
	madvFree      = 8 // MADV_FREE
	mremapMaymove = 1

	sigBlock   = 1 // SIG_BLOCK
	sigSetmask = 2 // SIG_SETMASK

	futexWait          = 0
	futexWake          = 1
	futexFd            = 2
	futexRequeue       = 3
	futexCmpRequeue    = 4
	futexWakeOp        = 5
	futexLockPi        = 6
	futexUnlockPi      = 7
	futexTrylockPi     = 8
	futexWaitBitset    = 9
	futexWakeBitset    = 10
	futexWaitRequeuePi = 11
	futexCmpRequeuePi  = 12

	futexPrivateFlag   = 128
	futexClockRealtime = 256

	futexWaitPrivate          = futexWait | futexPrivateFlag
	futexWakePrivate          = futexWake | futexPrivateFlag
	futexRequeuePrivate       = futexRequeue | futexPrivateFlag
	futexCmpRequeuePrivate    = futexCmpRequeue | futexPrivateFlag
	futexWakeOpPrivate        = futexWakeOp | futexPrivateFlag
	futexLockPiPrivate        = futexLockPi | futexPrivateFlag
	futexUnlockPiPrivate      = futexUnlockPi | futexPrivateFlag
	futexTrylockPiPrivate     = futexTrylockPi | futexPrivateFlag
	futexWaitBitsetPrivate    = futexWaitBitset | futexPrivateFlag
	futexWakeBitsetPrivate    = futexWakeBitset | futexPrivateFlag
	futexWaitRequeuePiPrivate = futexWaitRequeuePi | futexPrivateFlag
	futexCmpRequeuePiPrivate  = futexCmpRequeuePi | futexPrivateFlag

	pollIn = 1

	fionread  = 0x541b
	tcgets    = 0x5401
	tiocgpgrp = 0x540f

	// socketcall() call numbers (linux/net.h)
	sysSocket      = 1  // sys_socket()
	sysBind        = 2  // sys_bind()
	sysConnect     = 3  // sys_connect()
	sysListen      = 4  // sys_listen()
	sysAccept      = 5  // sys_accept()
	sysGetsockname = 6  // sys_getsockname()
	sysGetpeername = 7  // sys_getpeername()
	sysSocketpair  = 8  // sys_socketpair()
	sysSend        = 9  // sys_send()
	sysRecv        = 10 // sys_recv()
	sysSendto      = 11 // sys_sendto()
	sysRecvfrom    = 12 // sys_recvfrom()
	sysShutdown    = 13 // sys_shutdown()
	sysSetsockopt  = 14 // sys_setsockopt()
	sysGetsockopt  = 15 // sys_getsockopt()
	sysSendmsg     = 16 // sys_sendmsg()
	sysRecvmsg     = 17 // sys_recvmsg()
	sysAccept4     = 18 // sys_accept4()
	sysRecvmmsg    = 19 // sys_recvmmsg
	sysSendmmsg    = 20 // sys_sendmmsg
)

func newWhitelist(is386 bool) (*seccomp.ScmpFilter, error) {
	arch := seccomp.ArchAMD64
	if is386 {
		arch = seccomp.ArchX86
	}

	actENOSYS := seccomp.ActErrno.SetReturnCode(38)
	f, err := seccomp.NewFilter(actENOSYS)
	if err != nil {
		return nil, err
	}

	if err = f.AddArch(arch); err != nil {
		f.Release()
		return nil, err
	}
	if err = f.SetBadArchAction(seccomp.ActKill); err != nil {
		return nil, err
	}

	return f, nil
}

func allowSyscalls(f *seccomp.ScmpFilter, calls []string, is386 bool) error {
	for _, scallName := range calls {
		scall, err := seccomp.GetSyscallFromName(scallName)
		if err != nil {
			return fmt.Errorf("seccomp: unknown system call: %v", scallName)
		}
		if err = f.AddRule(scall, seccomp.ActAllow); err != nil {
			return err
		}
	}
	return nil
}

func allowCmpEq(f *seccomp.ScmpFilter, scallName string, arg uint, values ...uint64) error {
	scall, err := seccomp.GetSyscallFromName(scallName)
	if err != nil {
		return fmt.Errorf("seccomp: unknown system call: %v", scallName)
	}

	// Allow if the arg matches any of the values.  Implemented as multiple
	// rules.
	for _, v := range values {
		argIsEqual, err := seccomp.MakeCondition(arg, seccomp.CompareEqual, v)
		if err != nil {
			return err
		}
		if err = f.AddRuleConditional(scall, seccomp.ActAllow, []seccomp.ScmpCondition{argIsEqual}); err != nil {
			return err
		}
	}
	return nil
}
