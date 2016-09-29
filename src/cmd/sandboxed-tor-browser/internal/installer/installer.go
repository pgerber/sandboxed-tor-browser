// installer.go - Tor Browser installer.
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

// Package installer handles keeping Tor Browser up to date.
package installer

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"strings"

	"git.schwanenlied.me/yawning/bulb.git"
	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/openpgp"

	"cmd/sandboxed-tor-browser/internal/config"
	"cmd/sandboxed-tor-browser/internal/orhttp"
)

func slurp(ctrl *bulb.Conn, url string) ([]byte, error) {
	resp, err := orhttp.Get(ctrl, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func untar(r io.Reader, destDir string) error {
	if err := os.MkdirAll(destDir, os.ModeDir|0700); err != nil {
		return err
	}

	stripContainerDir := func(name string) string {
		// Go doesn't have a "split a path into all of it's components"
		// routine, because it's fucking retarded.
		split := strings.Split(name, "/")
		if len(split) > 1 {
			return path.Join(split[1:]...)
		}
		return ""
	}

	extractFile := func(dest string, hdr *tar.Header, r io.Reader) error {
		if hdr.Typeflag == tar.TypeSymlink {
			return fmt.Errorf("symlinks not supported: %v", dest)
		}

		f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, hdr.FileInfo().Mode())
		if err != nil {
			return err
		}
		defer os.Chtimes(dest, hdr.AccessTime, hdr.ModTime)
		defer f.Close()
		_, err = io.Copy(f, r)
		return err
	}

	tarRd := tar.NewReader(r)
	for {
		hdr, err := tarRd.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		name := stripContainerDir(hdr.Name)
		if name == "" {
			// Ensure that this is the container dir being skipped.
			if hdr.FileInfo().IsDir() {
				continue
			}
			return fmt.Errorf("expecting container dir, got file: %v", hdr.Name)
		}
		destName := path.Join(destDir, name)

		if hdr.FileInfo().IsDir() {
			if err := os.MkdirAll(destName, hdr.FileInfo().Mode()); err != nil {
				return err
			}
			continue
		}

		if err := extractFile(destName, hdr, tarRd); err != nil {
			return err
		}
	}
	return nil
}

func overrideBundlePrefs(cfg *config.Config) error {
	// Open the user preferences file for append only.
	//
	// This probably better belongs in preferences/extension-overrides.js,
	// since it's not something the user should mess with once the browser is
	// setup to run in sandboxed mode, but it's unclear to me how this will
	// interact with applying updates beyond "It will probably fuck things up".
	prefFile := path.Join(cfg.BundleInstallDir(), "Browser/TorBrowser/Data/Browser/profile.default/prefs.js")
	f, err := os.OpenFile(prefFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	// Change a few preferences to fit the sandboxed enviornment.
	//
	//  * Disable the Tor Browser updater - the lanucher handes keeping the
	//    bundle up to date.
	//  * Disable addon auto updates - The directory containing extensions
	//    will  be mounted read-only so this won't work.
	//
	// nb: Despite the Tor Browser (aka firefox) updater being disabled, it's
	// still possible to force a check via the "About Tor Browser" menu item
	// or via the torbutton menu item, and `about:tor` will still suggest you
	// do so.
	//
	// See: https://trac.torproject.org/projects/tor/ticket/20083
	const overriddenPrefs = `
user_pref("app.update.enabled", false);
user_pref("extensions.torbutton.versioncheck_enabled", false);
user_pref("extensions.update.enabled", false);`

	if _, err := f.WriteString(overriddenPrefs); err != nil {
		return err
	}

	return nil
}

func doInstall(cfg *config.Config, ctrl *bulb.Conn, onDisk *manifest, bundleDownloads *parsedDownloads) error {
	bundleDownloadEntry := bundleDownloads.Downloads[cfg.Architecture][cfg.Locale]

	// Update the manifest structure.
	onDisk.Channel = cfg.Channel
	onDisk.Architecture = cfg.Architecture
	onDisk.Locale = cfg.Locale
	onDisk.Version = bundleDownloads.Version

	// This routine throws the entire bundle into memory, so force a garbage
	// collection cycle as we return.
	defer runtime.GC()

	// Download the bundle over Tor.
	log.Printf("downloading bundle: %v", bundleDownloadEntry.Binary)
	bin, err := slurp(ctrl, bundleDownloadEntry.Binary)
	if err != nil {
		return fmt.Errorf("failed downloading bundle: %v", err)
	}

	// Download the bundle PGP signature over Tor.
	log.Printf("downloading signature: %v", bundleDownloadEntry.Sig)
	sig, err := slurp(ctrl, bundleDownloadEntry.Sig)
	if err != nil {
		return fmt.Errorf("failed downloading signature: %v", err)
	}

	// Validate the PGP signature.
	if ent, err := openpgp.CheckArmoredDetachedSignature(tbbKeyRing, bytes.NewReader(bin), bytes.NewReader(sig)); err != nil {
		return fmt.Errorf("invalid PGP signature: %v", err)
	} else if ent != tbbPgpKey {
		// Should never happen because there's only one key, and the signature
		// check returns an error, but this doesn't hurt...
		return fmt.Errorf("unexpected entity signed bundle: %v", ent)
	}

	// Obliterate the old bundle directory if it exists.
	os.RemoveAll(cfg.BundleInstallDir())

	// Extract the archive.
	log.Printf("extracting bundle")
	xzr, err := xz.NewReader(bytes.NewReader(bin))
	if err != nil {
		return fmt.Errorf("failed to initialize xz: %v", err)
	}
	if err := untar(xzr, cfg.BundleInstallDir()); err != nil {
		return fmt.Errorf("failed to untar: %v", err)
	}

	// Override bundle prefs.
	if err := overrideBundlePrefs(cfg); err != nil {
		return fmt.Errorf("failed overriding preferences: %v", err)
	}

	// Write the manifest and return.
	if err := onDisk.Write(cfg); err != nil {
		return fmt.Errorf("failed writing manifest: %v", err)
	}

	return nil
}

// Install installs/updates the Tor Browser bundle as needed, and returns the
// path to the bundle on disk.  All network requests are done via Tor,
// and signatures are validated where possible.
func Install(cfg *config.Config) error {
	// Connect to the control port so downloads can happen over Tor.
	ctrl, err := cfg.DialControlPort()
	if err != nil {
		return err
	}
	defer ctrl.Close()

	// Check the latest version.
	bundleDownloads, err := getBundleDownloads(cfg, ctrl)
	if err != nil {
		return err
	}

	// Ensure that the bundle configururation is valid.
	if bundleDownloads.Downloads[cfg.Architecture] == nil {
		return fmt.Errorf("invalid architecture: %v", cfg.Architecture)
	}
	if bundleDownloads.Downloads[cfg.Architecture][cfg.Locale] == nil {
		return fmt.Errorf("invalid locale: %v", cfg.Locale)
	}
	log.Printf("latest version: %v (%v)", bundleDownloads.Version, cfg.Channel)

	// Load the manifest file if any to determine what is present on disk.
	onDisk, err := loadManifest(cfg)
	if err != nil {
		return err
	} else if onDisk != nil {
		log.Printf("installed: %v (%v)", onDisk.Version, onDisk.Channel)
	}

	// Install, update, or do nothing.
	if onDisk == nil {
		log.Printf("installing bundle: no manifest present")
		onDisk = new(manifest) // Empty manifest.
	} else if onDisk.Channel != cfg.Channel {
		log.Printf("installing bundle: Channel mismatch")
	} else if onDisk.Architecture != cfg.Architecture {
		log.Printf("installing bundle: Architecture mismatch")
	} else if onDisk.Locale != cfg.Locale {
		log.Printf("installing bundle: Locale mismatch")
	} else if onDisk.Version != bundleDownloads.Version {
		// In theory Tor Browser has an auto-updater.  In practice, it probably
		// doesn't play well at all with the sandbox, so most of the
		// functionality will break.
		log.Printf("updating bundle: out of date")

		return doUpdate(cfg, ctrl, onDisk, bundleDownloads)
	} else {
		// Up to date.
		return nil
	}

	// Installation is required.
	return doInstall(cfg, ctrl, onDisk, bundleDownloads)
}
