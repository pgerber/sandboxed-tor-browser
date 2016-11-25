// ldso.go - Dynamic linker routines.
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

import (
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

var errUnsupported = errors.New("dynlib: unsupported os/architecture")

// GetLibraries returns the dynamic libraries imported by the given file at
// dynamic link time.
func GetLibraries(fn string) ([]string, error) {
	f, err := elf.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return f.ImportedLibraries()
}

// FindLdSo returns the path to the `ld.so` dynamic linker for the current
// architecture, which is usually a symlink
func FindLdSo(cache *Cache) (string, string, error) {
	if !IsSupported() {
		return "", "", errUnsupported
	}

	name := ""
	searchPaths := []string{}
	switch runtime.GOARCH {
	case "amd64":
		searchPaths = append(searchPaths, "/lib64")
		name = "ld-linux-x86-64.so.2"
	case "386":
		searchPaths = append(searchPaths, "/lib32")
		name = "ld-linux.so.2"
	default:
		panic("dynlib: unsupported architecture: " + runtime.GOARCH)
	}
	searchPaths = append(searchPaths, "/lib")

	for _, d := range searchPaths {
		candidate := filepath.Join(d, name)
		_, err := os.Stat(candidate)
		if err != nil {
			continue
		}

		actual := cache.GetLibraryPath(name)
		if actual == "" {
			continue
		}
		actual, err = filepath.EvalSymlinks(actual)

		return actual, candidate, err
	}

	return "", "", os.ErrNotExist
}

// IsSupported returns true if the architecture/os combination has dynlib
// sypport.
func IsSupported() bool {
	// XXX: 386 eventually.
	return runtime.GOOS == "linux" && runtime.GOARCH == "amd64"
}
