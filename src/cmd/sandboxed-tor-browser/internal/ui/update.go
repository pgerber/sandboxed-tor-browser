// update.go - Update logic.
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
	"log"

	"cmd/sandboxed-tor-browser/internal/installer"
	"cmd/sandboxed-tor-browser/internal/sandbox"
	. "cmd/sandboxed-tor-browser/internal/ui/async"
)

func (c *Common) CheckUpdate(async *Async, dialFn dialFunc) *installer.UpdateEntry {
	// Check for updates.
	log.Printf("update: Checking for updates.")
	async.UpdateProgress("Checking for updates.")

	// Create the async HTTP client.
	client := newHPKPGrabClient(dialFn)

	// Determine where the update metadata should be fetched from.
	updateURLs := []string{}
	for _, b := range []bool{true, false} { // Prioritize .onions.
		if url, err := installer.UpdateURL(c.Manif, b); err != nil {
			log.Printf("update: Failed to get update URL (onion: %v): %v", b, err)
		} else {
			updateURLs = append(updateURLs, url)
		}
	}
	if len(updateURLs) == 0 {
		log.Printf("update: Failed to find any update URLs")
		async.Err = fmt.Errorf("failed to find any update URLs")
		return nil
	}

	// Check the version, by downloading the XML file.
	var update *installer.UpdateEntry
	fetchOk := false
	for _, url := range updateURLs {
		log.Printf("update: Metadata URL: %v", url)
		async.Err = nil // Clear errors per fetch.
		if b := async.Grab(client, url, nil); async.Err != nil {
			log.Printf("update: Metadata download failed: %v", async.Err)
			continue
		} else if update, async.Err = installer.GetUpdateEntry(b); async.Err != nil {
			log.Printf("update: Metadata parse failed: %v", async.Err)
			continue
		}
		fetchOk = true
		break
	}

	if !fetchOk {
		// This should be set from the last update attempt...
		if async.Err == nil {
			async.Err = fmt.Errorf("failed to download update metadata")
		}
		return nil
	}

	if update == nil {
		log.Printf("update: Installed bundle is current.")
		c.Cfg.SetForceUpdate(false)
	} else {
		log.Printf("update: Installed bundle needs updating.")
		c.Cfg.SetForceUpdate(true)
	}

	if async.Err = c.Cfg.Sync(); async.Err != nil {
		return nil
	}

	return update
}

func (c *Common) doUpdate(async *Async, dialFn dialFunc) {
	// This attempts to follow the process that Firefox uses to check for
	// updates.  https://wiki.mozilla.org/Software_Update:Checking_For_Updates

	// Check for updates.
	update := c.CheckUpdate(async, dialFn)
	if async.Err != nil || update == nil {
		return
	}

	// Ensure that the update entry version is actually neweer.
	if !c.Manif.BundleUpdateVersionValid(update.AppVersion) {
		log.Printf("update: Update server provided a downgrade: '%v'", update.AppVersion)
		async.Err = fmt.Errorf("update server provided a downgrade: '%v'", update.AppVersion)
		return
	}

	// Figure out the best MAR to download.
	patches := make(map[string]*installer.Patch)
	for _, v := range update.Patch {
		if patches[v.Type] != nil {
			async.Err = fmt.Errorf("duplicate patch entry for kind: '%v'", v.Type)
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
	client := newHPKPGrabClient(dialFn)
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
		async.Err = fmt.Errorf("unsupported hash function: '%v'", patch.HashFunction)
		return
	}

	// ... and verify the signature block in the MAR with our copy of the key.
	if async.Err = installer.VerifyTorBrowserMAR(mar); async.Err != nil {
		return
	}

	// Shutdown the old tor now.
	if c.tor != nil {
		log.Printf("update: Shutting down old tor.")
		c.tor.Shutdown()
		c.tor = nil
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
	c.Cfg.SetForceUpdate(false)
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
