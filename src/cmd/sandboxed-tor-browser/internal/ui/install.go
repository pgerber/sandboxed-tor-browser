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
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"runtime"
	"time"

	"cmd/sandboxed-tor-browser/internal/data"
	"cmd/sandboxed-tor-browser/internal/installer"
	"cmd/sandboxed-tor-browser/internal/sandbox"
	. "cmd/sandboxed-tor-browser/internal/ui/async"
	"cmd/sandboxed-tor-browser/internal/ui/config"
	"cmd/sandboxed-tor-browser/internal/utils"
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
		async.Err = err
		return
	}

	// Create the async HTTP client.
	client := newHPKPGrabClient(dialFn)

	// Download the JSON file showing where the bundle files are.
	log.Printf("install: Checking available downloads.")
	async.UpdateProgress("Checking available downloads.")

	var version string
	var downloads *installer.DownloadsEntry
	if url := installer.DownloadsURL(c.Cfg); url == "" {
		async.Err = fmt.Errorf("unable to find downloads URL")
		return
	} else if b := async.Grab(client, url, nil); async.Err != nil {
		return
	} else if version, downloads, async.Err = installer.GetDownloadsEntry(c.Cfg, b); async.Err != nil {
		return
	}
	checkAt := time.Now().Unix()

	log.Printf("install: Version: %v Downloads: %v", version, downloads)

	// Download the bundle.
	log.Printf("install: Downloading %v", downloads.Binary)
	async.UpdateProgress("Downloading Tor Browser.")

	var bundleTarXz []byte
	if bundleTarXz = async.Grab(client, downloads.Binary, func(s string) { async.UpdateProgress(fmt.Sprintf("Downloading Tor Browser: %s", s)) }); async.Err != nil {
		return
	}

	// Download the signature.
	log.Printf("install: Downloading %v", downloads.Sig)
	async.UpdateProgress("Downloading Tor Browser PGP Signature.")

	var bundleSig []byte
	if bundleSig = async.Grab(client, downloads.Sig, nil); async.Err != nil {
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

	// Install the autoconfig stuff.
	if async.Err = writeAutoconfig(c.Cfg); async.Err != nil {
		return
	}

	// Set the manifest.
	c.Manif = config.NewManifest(c.Cfg, version)
	if async.Err = c.Manif.Sync(); async.Err != nil {
		return
	}

	// Set the appropriate bits in the config.
	c.Cfg.SetLastUpdateCheck(checkAt)
	c.Cfg.SetFirstLaunch(true)

	// Sync the config, and return.
	async.Err = c.Cfg.Sync()
}

func writeAutoconfig(cfg *config.Config) error {
	autoconfigFile := filepath.Join(cfg.BundleInstallDir, "Browser", "defaults", "pref", "autoconfig.js")
	if b, err := data.Asset("installer/autoconfig.js"); err != nil {
		return err
	} else if err = ioutil.WriteFile(autoconfigFile, b, utils.FileMode); err != nil {
		return err
	}

	mozillacfgFile := filepath.Join(cfg.BundleInstallDir, "Browser", "mozilla.cfg")
	if b, err := data.Asset("installer/mozilla.cfg"); err != nil {
		return err
	} else if err = ioutil.WriteFile(mozillacfgFile, b, utils.FileMode); err != nil {
		return err
	}

	return nil
}

func (c *Common) doUpdate(async *Async, dialFn dialFunc) {
	// This attempts to follow the process that Firefox uses to check for
	// updates.  https://wiki.mozilla.org/Software_Update:Checking_For_Updates

	// Check for updates.
	log.Printf("launch: Checking for updates.")
	async.UpdateProgress("Checking for updates.")

	// Create the async HTTP client.
	client := newHPKPGrabClient(dialFn)

	// Check the version, by downloading the XML file.
	var update *installer.UpdateEntry
	if url, err := installer.UpdateURL(c.Manif); err != nil {
		async.Err = err
		return
	} else {
		log.Printf("launch: Update URL: %v", url)
		if b := async.Grab(client, url, nil); async.Err != nil {
			return
		} else if update, async.Err = installer.GetUpdateEntry(b); async.Err != nil {
			return
		}
	}

	checkAt := time.Now().Unix()
	if update == nil {
		log.Printf("launch: Installed bundle is current.")

		// Save the time that the update check was done.
		c.Cfg.SetLastUpdateCheck(checkAt)
		async.Err = c.Cfg.Sync()
		return
	}

	// Force an update check again if the user exits for any reason, since
	// we know there is an update available.
	c.Cfg.SetLastUpdateCheck(0)
	if async.Err = c.Cfg.Sync(); async.Err != nil {
		return
	}

	// Figure out the best MAR to download.
	patches := make(map[string]*installer.Patch)
	for _, v := range update.Patch {
		if patches[v.Type] != nil {
			async.Err = fmt.Errorf("duplicate patch entry for kind: %v", v.Type)
			return
		}
		patches[v.Type] = &v
	}
	patch := patches["partial"] // Favor the delta update mechanism.
	if patch == nil {
		if patch = patches["complete"]; patch == nil {
			async.Err = fmt.Errorf("no suitable MAR file found")
			return
		}
	}

	// Download the MAR file.
	log.Printf("update: Downloading %v", patch.Url)
	async.UpdateProgress("Downloading Tor Browser Update.")

	var mar []byte
	if mar = async.Grab(client, patch.Url, func(s string) { async.UpdateProgress(fmt.Sprintf("Downloading Tor Browser Update: %s", s)) }); async.Err != nil {
		return
	}

	log.Printf("update: Validating Tor Browser Update.")
	async.UpdateProgress("Validating Tor Browser Update.")

	// Validate the hash against that listed in the XML file.
	expectedHash, err := hex.DecodeString(patch.HashValue)
	if err != nil {
		async.Err = fmt.Errorf("failed to decode HashValue: %v", err)
		return
	}
	switch patch.HashFunction {
	case "SHA512":
		derivedHash := sha512.Sum512(mar)
		if !bytes.Equal(expectedHash, derivedHash[:]) {
			async.Err = fmt.Errorf("downloaded hash does not match patch metadata")
			return
		}
	default:
		async.Err = fmt.Errorf("unsupported hash function: %v", patch.HashFunction)
		return
	}

	// ... and verify the signature block in the MAR with our copy of the key.
	if async.Err = installer.VerifyTorBrowserMAR(mar); async.Err != nil {
		return
	}

	// Apply the update.
	log.Printf("update: Updating Tor Browser.")
	async.UpdateProgress("Updating Tor Browser.")

	async.ToUI <- false //  Lock out canceling.

	if async.Err = sandbox.RunUpdate(c.Cfg, mar); async.Err != nil {
		return
	}

	// Reinstall the autoconfig stuff.
	if async.Err = writeAutoconfig(c.Cfg); async.Err != nil {
		return
	}

	// Update the maniftest and config.
	c.Manif.SetVersion(update.AppVersion)
	if async.Err = c.Manif.Sync(); async.Err != nil {
		return
	}
	c.Cfg.SetLastUpdateCheck(checkAt)
	if async.Err = c.Cfg.Sync(); async.Err != nil {
		return
	}

	async.ToUI <- true // Unlock canceling.

	// Restart tor if we launched it.
	if !c.Cfg.UseSystemTor {
		log.Printf("launch: Reconnecting to the Tor network.")
		async.UpdateProgress("Reconnecting to the Tor network.")
		_, async.Err = c.launchTor(async, false)
	}
	return
}
