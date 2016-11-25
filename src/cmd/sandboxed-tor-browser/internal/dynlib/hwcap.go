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

import "runtime"

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
