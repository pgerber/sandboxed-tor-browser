// updater.go - Tor Browser updater.
// Copyright (C) 2016  Yawning Angel.
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/.

// Package installer handles keeping Tor Browser up to date.
package installer

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log"
	"runtime"

	"git.schwanenlied.me/yawning/bulb.git"

	"cmd/sandboxed-tor-browser/internal/config"
	"cmd/sandboxed-tor-browser/internal/orhttp"
	"cmd/sandboxed-tor-browser/internal/sandbox"
)

type parsedUpdates struct {
	XMLName xml.Name       `xml:"updates"`
	Update  []parsedUpdate `xml:"update"`
}

type parsedUpdate struct {
	Type            string        `xml:"type,attr"`
	DisplayVersion  string        `xml:"displayVersion,attr"`
	AppVersion      string        `xml:"appVersion,attr"`
	PlatformVersion string        `xml:"platformVersion,attr"`
	BuildID         string        `xml:"buildID,attr"`
	DetailsURL      string        `xml:"detailsURL,attr"`
	Actions         string        `xml:"actions,attr"`
	OpenURL         string        `xml:"openURL,attr"`
	Patch           []parsedPatch `xml:"patch"`
}

type parsedPatch struct {
	Url          string `xml:"URL,attr"`
	HashFunction string `xml:"hashFunction,attr"`
	HashValue    string `xml:"hashValue,attr"`
	Size         int    `xml:"size,attr"`
	Type         string `xml:"type,attr"`
}

func getMARDownloads(ctrl *bulb.Conn, url string) (*parsedUpdates, error) {
	// Fetch the MAR containing the update.
	response, err := orhttp.Get(ctrl, url, distTpoCertChain)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Parse the XML file.
	//
	// https://wiki.mozilla.org/Software_Update:updates.xml_Format
	updates := &parsedUpdates{}
	dec := xml.NewDecoder(response.Body)
	if err := dec.Decode(&updates); err != nil {
		return nil, err
	}

	return updates, nil
}

func doUpdate(cfg *config.Config, ctrl *bulb.Conn, onDisk *manifest, bundleDownloads *parsedDownloads) error {
	// Obtain the URL pointing to the XML file listing MAR file(s) available
	//to download.
	//
	// https://wiki.mozilla.org/Software_Update:Checking_For_Updates
	arch := ""
	switch cfg.Architecture {
	case "linux64":
		arch = "Linux_x86_64-gcc3"
	case "linux32":
		arch = "Linux_x86-gcc3"
	default:
		return fmt.Errorf("unsupported architecture for update: %v", cfg.Architecture)
	}
	url := fmt.Sprintf("https://dist.torproject.org/torbrowser/update_2/%s/%s/%s/%s", cfg.Channel, arch, onDisk.Version, cfg.Locale)

	// Fetch and parse the XML file.
	updates, err := getMARDownloads(ctrl, url)
	if err != nil {
		return err
	}

	// Figure out the best MAR to download.
	if len(updates.Update) != 1 {
		return fmt.Errorf("more than one update listed in the XML file")
	}
	update := updates.Update[0]
	if bundleDownloads.Version != update.AppVersion {
		return fmt.Errorf("version mismatch between JSON (%v) and XML files (%v)", bundleDownloads.Version, update.AppVersion)
	}
	patches := make(map[string]*parsedPatch)
	for _, v := range update.Patch {
		if patches[v.Type] != nil {
			return fmt.Errorf("duplicate patch entry for kind: %v", v.Type)
		}
		patches[v.Type] = &v
	}
	patch := patches["partial"] // Favor the delta update mechanism.
	if patch == nil {
		if patch = patches["complete"]; patch == nil {
			return fmt.Errorf("no suitable MAR file found")
		}
	}

	// This routine trhows the entire update into memory, so force a garbage
	// collection cycle as we return.
	defer runtime.GC()

	// Fetch the MAR file.
	log.Printf("downloading update: %v", patch.Url)
	bin, err := slurp(ctrl, patch.Url)
	if err != nil {
		return fmt.Errorf("failed downloading update: %v", err)
	}

	// Validate the hash agains that listed in the XML file.
	expectedHash, err := hex.DecodeString(patch.HashValue)
	if err != nil {
		return fmt.Errorf("failed to decode HashValue: %v", err)
	}
	switch patch.HashFunction {
	case "SHA512":
		derivedHash := sha512.Sum512(bin)
		if !bytes.Equal(expectedHash, derivedHash[:]) {
			return fmt.Errorf("downloaded hash does not match patch metadata")
		}
	default:
		return fmt.Errorf("unsupported hash function: %v", patch.HashFunction)
	}

	// Verify the signature block in the MAR with our copy of the key.
	if err = verifyTorBrowserMAR(bin); err != nil {
		return fmt.Errorf("failed to verify MAR signature: %v", err)
	}

	// Install the MAR using the `updater` executable, in a sandboxed
	// enviornment.
	if err := sandbox.RunUpdate(cfg, bin); err != nil {
		return fmt.Errorf("failed applying update: %v", err)
	}

	// Write out the new manifest and return
	onDisk.Version = update.AppVersion
	if err := onDisk.Write(cfg); err != nil {
		return fmt.Errorf("failed writing manifest: %v", err)
	}

	return nil
}
