// install.go - Install/Update logic.
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

package ui

import (
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"

	"git.schwanenlied.me/yawning/grab.git"

	"cmd/sandboxed-tor-browser/internal/installer"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

// DoInstall executes the install step based on the configured parameters.
// This is blocking and should be run from a go routine, with the appropriate
// Async structure used to communicate.
func (c *Common) DoInstall(async *Async) {
	var err error
	async.Err = nil
	defer func() {
		if async.Err != nil {
			log.Printf("install: Failing with error: %v", async.Err)
		} else {
			log.Printf("install: Complete.")
		}
		runtime.GC()
		async.Done <- true
	}()

	log.Printf("install: Starting.")

	if c.tor != nil {
		log.Printf("install: Shutting down old tor.")
		c.tor.Shutdown()
		c.tor = nil
	}

	// Get the Dial() routine used to reach the external network.
	dialFn, err := c.launchTor(async, true)
	if err != nil {
		return
	}
	// XXX: Wrap dialFn in a HPKP dialer.

	// Create the async HTTP client.
	client := grab.NewClient()
	client.UserAgent = ""
	client.HTTPClient.Transport = &http.Transport{
		Proxy: nil,
		Dial:  dialFn,
	}

	// Download the JSON file showing where the bundle files are.
	log.Printf("install: Checking available downloads.")
	async.UpdateProgress("Checking available downloads.")

	var version string
	var downloads *installer.DownloadsEntry
	if url := installer.DownloadsURL(c.Cfg); url == "" {
		async.Err = fmt.Errorf("unable to find downloads URL")
		return
	} else if b := async.grab(client, url, nil); async.Err != nil {
		return
	} else if version, downloads, err = installer.GetDownloadsEntry(c.Cfg, b); err != nil {
		async.Err = err
		return
	}
	checkAt := time.Now().Unix()

	log.Printf("install: Version: %v Downloads: %v", version, downloads)

	// Download the bundle.
	log.Printf("install: Downloading %v", downloads.Binary)
	async.UpdateProgress("Downloading Tor Browser.")

	var bundleTarXz []byte
	if bundleTarXz = async.grab(client, downloads.Binary, func(s string) { async.UpdateProgress(fmt.Sprintf("Downloading Tor Browser: %s", s)) }); async.Err != nil {
		return
	}

	// Download the signature.
	log.Printf("install: Downloading %v", downloads.Sig)
	async.UpdateProgress("Downloading Tor Browser PGP Signature.")

	var bundleSig []byte
	if bundleSig = async.grab(client, downloads.Sig, nil); async.Err != nil {
		return
	}

	// Check the signature.
	log.Printf("install: Validating Tor Browser PGP Signature.")
	async.UpdateProgress("Validating Tor Browser PGP Signature.")

	if async.Err = installer.ValidatePGPSignature(bundleTarXz, bundleSig); async.Err != nil {
		return
	}

	// Install the bundle.
	log.Printf("install: Installing Tor Browser.")
	async.UpdateProgress("Installing Tor Browser.")

	if err := installer.ExtractBundle(c.Cfg.BundleInstallDir, bundleTarXz, async.Cancel); err != nil {
		async.Err = err
		if async.Err == installer.ErrExtractionCanceled {
			async.Err = ErrCanceled
		}
		return
	}

	// Lock out and ignore cancelation, since things are basically done.
	async.ToUI <- false

	// XXX: Install the autoconfig stuff.

	// Set the manifest portion of the config.
	c.Cfg.SetInstalled(&config.Installed{
		Version:         version,
		Architecture:    c.Cfg.Architecture,
		Channel:         c.Cfg.Channel,
		Locale:          c.Cfg.Locale,
		LastUpdateCheck: checkAt,
	})

	// Sync the config, and return.
	async.Err = c.Cfg.Sync()
}
