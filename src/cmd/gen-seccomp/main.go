// gen-seccomp.go - Pre-generate seccomp rules.
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
	"flag"
	"log"
	"os"
	"path/filepath"
)

func main() {
	outFlag := flag.String("o", "", "output directory")
	flag.Parse()

	outDir, err := filepath.Abs(*outFlag)
	if err != nil {
		log.Fatalf("failed to get absolute path: %v", err)
	}

	// Tor Browser (amd64)
	f, err := os.Create(filepath.Join(outDir, "tor-amd64.bpf"))
	if err != nil {
		log.Fatalf("failed to create output: %v", err)
	}
	if err = compileTorSeccompProfile(f, false, false); err != nil {
		log.Fatalf("failed to create tor amd64 profile: %v", err)
	}

	// Tor Browser + obfs4proxy (amd64)
	f, err = os.Create(filepath.Join(outDir, "tor-obfs4-amd64.bpf"))
	if err != nil {
		log.Fatalf("failed to create output: %v", err)
	}
	if err = compileTorSeccompProfile(f, true, false); err != nil {
		log.Fatalf("failed to create tor-obfs4 amd64 profile: %v", err)
	}

	// Firefox (amd64)
	f, err = os.Create(filepath.Join(outDir, "torbrowser-amd64.bpf"))
	if err != nil {
		log.Fatalf("failed to create output: %v", err)
	}
	if err = compileTorBrowserSeccompProfile(f, false); err != nil {
		log.Fatalf("failed to create firefox amd64 profile: %v", err)
	}

	// Tor Browser (386)
	f, err = os.Create(filepath.Join(outDir, "tor-386.bpf"))
	if err != nil {
		log.Fatalf("failed to create output: %v", err)
	}
	if err = compileTorSeccompProfile(f, false, true); err != nil {
		log.Fatalf("failed to create tor 386 profile: %v", err)
	}

	// Tor Browser + obfs4proxy (386)
	f, err = os.Create(filepath.Join(outDir, "tor-obfs4-386.bpf"))
	if err != nil {
		log.Fatalf("failed to create output: %v", err)
	}
	if err = compileTorSeccompProfile(f, true, true); err != nil {
		log.Fatalf("failed to create tor-obfs4 386 profile: %v", err)
	}

	// Firefox (386)
	f, err = os.Create(filepath.Join(outDir, "torbrowser-386.bpf"))
	if err != nil {
		log.Fatalf("failed to create output: %v", err)
	}
	if err = compileTorBrowserSeccompProfile(f, true); err != nil {
		log.Fatalf("failed to create firefox 386 profile: %v", err)
	}
}
