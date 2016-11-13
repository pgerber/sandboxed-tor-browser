// application.go - Tor Browser sandbox launch routines.
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

// Package sandbox handles launching applications in a sandboxed enviornment
// via bubblwrap.
package sandbox

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"

	"cmd/sandboxed-tor-browser/internal/tor"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

const (
	controlSocket = "control"
	socksSocket   = "socks"
)

// RunTorBrowser launches sandboxed Tor Browser.
func RunTorBrowser(cfg *config.Config, tor *tor.Tor) (cmd *exec.Cmd, err error) {
	const (
		profileSubDir = "TorBrowser/Data/Browser/profile.default"
		cachesSubDir  = "TorBrowser/Data/Browser/Caches"
		stubPath      = "/tmp/tbb_stub.so"
	)

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	h, err := newHugbox()
	if err != nil {
		return nil, err
	}
	h.stdout = os.Stdout // XXX: This should be redirected.
	h.stderr = os.Stderr
	h.seccompFn = installBasicBlacklist // XXX: Use something better.

	// X11, Gtk+, and PulseAudio.
	if err = h.enableX11(cfg.Sandbox.Display); err != nil {
		return
	}
	h.roBind("/usr/share/themes", "/usr/share/themes", false)
	h.roBind("/usr/share/icons", "/usr/share/icons", false)
	h.roBind("/usr/share/mime", "/usr/share/mime", false)
	gtkRcPath := path.Join(h.homeDir, ".gtkrc-2.0")
	h.setenv("GTK2_RC_FILES", gtkRcPath)
	h.assetFile(gtkRcPath, "gtkrc-2.0")
	if cfg.Sandbox.EnablePulseAudio {
		if err = h.enablePulseAudio(); err != nil {
			log.Printf("sandbox: failed to proxy PulseAudio: %v", err)
		}
	}

	browserHome := path.Join(h.homeDir, "sandboxed-tor-browser", "tor-browser", "Browser")
	realBrowserHome := path.Join(cfg.BundleInstallDir, "Browser")
	realProfileDir := path.Join(realBrowserHome, profileSubDir)
	realCachesDir := path.Join(realBrowserHome, cachesSubDir)
	realDesktopDir := path.Join(realBrowserHome, "Desktop")
	realDownloadsDir := path.Join(realBrowserHome, "Downloads")

	// Ensure that the `Downloads` and `Desktop` mount points exist.
	if err = os.MkdirAll(realDesktopDir, os.ModeDir|0700); err != nil {
		return
	}
	if err = os.MkdirAll(realDownloadsDir, os.ModeDir|0700); err != nil {
		return
	}

	// Apply directory overrides.
	if cfg.Sandbox.DesktopDir != "" {
		realDesktopDir = cfg.Sandbox.DesktopDir
	}
	if cfg.Sandbox.DownloadsDir != "" {
		realDownloadsDir = cfg.Sandbox.DownloadsDir
	}

	profileDir := path.Join(browserHome, profileSubDir)
	cachesDir := path.Join(browserHome, cachesSubDir)
	downloadsDir := path.Join(browserHome, "Downloads")
	desktopDir := path.Join(browserHome, "Desktop")

	// Filesystem stuff.
	h.roBind(cfg.UserDataDir, "/home/amnesia/sandboxed-tor-browser", false)
	h.bind(realProfileDir, profileDir, false)
	h.bind(realDesktopDir, desktopDir, false)
	h.bind(realDownloadsDir, downloadsDir, false)
	h.bind(realCachesDir, cachesDir, false) // XXX: Do I need this?
	h.roBind(path.Join(realProfileDir, "preferences"), path.Join(profileDir, "preferences"), false)
	h.chdir = browserHome
	if !cfg.Sandbox.VolatileExtensionsDir {
		// Unless overridden, the extensions directory should be mounted
		// read-only.
		h.roBind(path.Join(realProfileDir, "extensions"), path.Join(profileDir, "extensions"), false)
	}

	// Env vars taken from start-tor-browser.
	h.setenv("LD_LIBRARY_PATH", path.Join(browserHome, "TorBrowser", "Tor"))
	h.setenv("FONTCONFIG_PATH", path.Join(browserHome, "TorBrowser", "Data", "fontconfig"))
	h.setenv("FONTCONFIG_FILE", "fonts.conf")
	h.setenv("ASAN_OPTIONS", "detect_leaks=0") // For hardened.

	// GNOME systems will puke with a read-only home, so instead of setting
	// $HOME to point to inside the browser bundle, setup a bunch of
	// symlinks.
	//
	// `XDG_[DOWNLOAD,DESKTOP]_DIR` appear to be honored if they are in
	// `~/.config/user-dirs.dirs`, but are ignored if specified as env
	// vars.  The symlink approach is probably more user friendly anyway.
	//
	// h.setenv("HOME", browserHome)
	h.symlink(desktopDir, "/home/amnesia/Desktop")
	h.symlink(downloadsDir, "/home/amnesia/Downloads")

	// Set the same env vars that Tor Browser would expect when using a system
	// tor, since the launcher is responsible for managing the Tor process, and
	// it will be talking to the surrogates anyway.
	h.setenv("TOR_SOCKS_PORT", "9150")
	h.setenv("TOR_CONTROL_PORT", "9151")
	h.setenv("TOR_SKIP_LAUNCH", "1")
	h.setenv("TOR_NO_DISPLAY_NETWORK_SETTINGS", "1")

	// Launch the control/socks port surrogates.  They will be torn down if
	// the launch fails in a manner that the UI can recover.
	socks, err := launchSocksProxy(cfg, tor)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			socks.close()
		}
	}()
	ctrl, err := launchCtrlProxy(cfg, socks, tor)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			ctrl.close()
		}
	}()

	// Inject the AF_LOCAL compatibility hack stub into the filesystem, and
	// supply the relevant args required for functionality.
	ctrlPath := path.Join(h.runtimeDir, controlSocket)
	socksPath := path.Join(h.runtimeDir, socksSocket)
	h.setenv("LD_PRELOAD", stubPath)
	h.setenv("TOR_STUB_CONTROL_SOCKET", ctrlPath)
	h.setenv("TOR_STUB_SOCKS_SOCKET", socksPath)
	h.bind(path.Join(cfg.RuntimeDir, controlSocket), ctrlPath, false)
	h.bind(path.Join(cfg.RuntimeDir, socksSocket), socksPath, false)
	h.assetFile(stubPath, "tbb_stub.so")

	h.cmd = path.Join(browserHome, "firefox")
	h.cmdArgs = []string{"--class", "Tor Browser", "-profile", profileDir}

	return h.run()
}

// RunUpdate launches sandboxed Tor Browser update.
func RunUpdate(cfg *config.Config, mar []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	h, err := newHugbox()
	if err != nil {
		return err
	}
	h.stdout = os.Stdout // XXX: This should be redirected.
	h.stderr = os.Stderr
	h.seccompFn = installBasicBlacklist // XXX: Use something better.

	// https://wiki.mozilla.org/Software_Update:Manually_Installing_a_MAR_file
	const (
		installDir = "/home/amnesia/sandboxed-tor-browser/tor-browser"
		updateDir  = "/home/amnesia/sandboxed-tor-browser/update"
	)

	browserHome := path.Join(h.homeDir, "sandboxed-tor-browser", "tor-browser", "Browser")
	realInstallDir := cfg.BundleInstallDir
	realUpdateDir := path.Join(cfg.UserDataDir, "update")

	// Do the work neccecary to make the firefox `updater` happy.
	if err = stageUpdate(realUpdateDir, realInstallDir, mar); err != nil {
		return err
	}

	h.bind(realInstallDir, installDir, false)
	h.bind(realUpdateDir, updateDir, false)
	h.chdir = browserHome // Required (Step 5.)
	h.setenv("LD_LIBRARY_PATH", browserHome)

	// 7. For Firefox 40.x and above run the following from the command prompto
	//    after adding the path to the existing installation directory to the
	//    LD_LIBRARY_PATH environment variable.
	h.cmd = path.Join(updateDir, "updater")
	h.cmdArgs = []string{updateDir, browserHome, browserHome}
	cmd, err := h.run()
	if err != nil {
		return err
	}
	cmd.Wait()

	// 8. After the update has completed a file named update.status will be
	//    created in the outside directory.
	status, err := ioutil.ReadFile(path.Join(realUpdateDir, "update.status"))
	if err != nil {
		return err
	}
	trimmedStatus := bytes.TrimSpace(status)
	if !bytes.Equal(trimmedStatus, []byte("succeeded")) {
		return fmt.Errorf("failed to apply update: %v", string(trimmedStatus))
	}

	// Since the update was successful, clean out the "outside" directory.
	os.RemoveAll(realUpdateDir)

	return nil
}

func stageUpdate(updateDir, installDir string, mar []byte) error {
	copyFile := func(src, dst string) error {
		// stat() the source file to get the file mode.
		fi, err := os.Lstat(src)
		if err != nil {
			return err
		}

		// Read the source file into memory.
		b, err := ioutil.ReadFile(src)
		if err != nil {
			return err
		}

		// Create and write the destination file.
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode())
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(b)
		f.Sync()

		return err
	}

	// 1. Create a directory outside of the application's installation
	//    directory to be updated.
	if err := os.MkdirAll(updateDir, os.ModeDir|0700); err != nil {
		return err
	}

	// 2. Copy updater from the application's installation directory that is
	//    to be upgraded into the outside directory. If you would like to
	//    display the updater user interface while it is applying the update
	//    also copy the updater.ini into the outside directory.
	if err := copyFile(path.Join(installDir, "Browser", "updater"), path.Join(updateDir, "updater")); err != nil {
		return err
	}

	// 3. Download the appropriate .mar file and put it into the outside
	//    directory you created (see Where to get a mar file).
	// 4. Rename the mar file you downloaded to update.mar.
	if err := ioutil.WriteFile(path.Join(updateDir, "update.mar"), mar, 0600); err != nil {
		return err
	}

	return nil
}
