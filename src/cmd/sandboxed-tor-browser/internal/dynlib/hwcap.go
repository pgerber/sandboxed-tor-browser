// hwcap.go - ld.so.conf hwcap routines.
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

package dynlib

// #include <sys/auxv.h>
//
// static char * getPlatform() {
//   return (char *)getauxval(AT_PLATFORM);
// }
//
import "C"

import (
	"bytes"
	"runtime"
	"syscall"
)

const (
	x86HwcapFirstPlatform = 48
	hwcapMask             = 0xffffffff
)

func getHwcap() uint64 {
	if runtime.GOARCH != "386" {
		return 0
	}

	// HWCAP_I386_XMM2  = 1 << 26
	// HWCAP_I386_CMOV  = 1 << 15 (Debian-ism)
	important := uint32((1 << 26) | (1 << 15))
	hwcap := uint64(uint32(C.getauxval(C.AT_HWCAP)) & important)

	// On x86, glibc stores the x86 architecture family in hwcap as well.
	x86Platforms := []string{"i386", "i486", "i586", "i686"}

	platform := C.GoString(C.getPlatform())
	for i, v := range x86Platforms {
		if v == platform {
			i += x86HwcapFirstPlatform
			hwcap = hwcap | (uint64(i) << x86HwcapFirstPlatform)
			break
		}
	}

	return hwcap
}

func getOsVersion() uint32 {
	var buf syscall.Utsname
	err := syscall.Uname(&buf)
	if err != nil {
		panic(err)
	}

	// Split into a slice of digits, stopping when the first non-digit is
	// encountered.
	var relBuf []byte
	for _, v := range buf.Release {
		if (v < '0' || v > '9') && v != '.' {
			break
		}
		relBuf = append(relBuf, byte(v))
	}

	// Parse major, minor, pl into bytes, and jam them together.
	//
	// glibc as far as I can tell doesn't handle any of versions being larger
	// than 256 at all.
	var ret uint32
	appended := uint(0)
	for i, v := range bytes.Split(relBuf, []byte{'.'}) {
		if i > 2 {
			break
		}
		var subVer uint8
		for _, b := range v {
			subVer = subVer * 10
			subVer = subVer + (b - '0')
		}
		ret = ret << 8
		ret = ret | uint32(subVer)
		appended++
	}
	return ret << (8 * (3 - appended))
}
