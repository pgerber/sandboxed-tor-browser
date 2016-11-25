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
	"path/filepath"
	"runtime"
	"sort"
	"syscall"

	"cmd/sandboxed-tor-browser/internal/dynlib"
	"cmd/sandboxed-tor-browser/internal/tor"
	"cmd/sandboxed-tor-browser/internal/ui/config"
	. "cmd/sandboxed-tor-browser/internal/utils"
)

const restrictedLibDir = "/usr/lib"

var distributionDependentLibSearchPath []string

// RunTorBrowser launches sandboxed Tor Browser.
func RunTorBrowser(cfg *config.Config, manif *config.Manifest, tor *tor.Tor) (cmd *exec.Cmd, err error) {
	const (
		profileSubDir = "TorBrowser/Data/Browser/profile.default"
		cachesSubDir  = "TorBrowser/Data/Browser/Caches"
		stubPath      = "/tmp/tbb_stub.so"
		controlSocket = "control"
		socksSocket   = "socks"
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

	logger := newConsoleLogger("firefox")
	h.stdout = logger
	h.stderr = logger
	h.seccompFn = installTorBrowserSeccompProfile
	h.fakeDbus = true

	// X11, Gtk+, and PulseAudio.
	if err = h.enableX11(cfg.Sandbox.Display); err != nil {
		return
	}
	h.roBind("/usr/share/themes/Adwaita/gtk-2.0", "/usr/share/themes/Adwaita/gtk-2.0", false)
	h.roBind("/usr/share/icons/Adwaita", "/usr/share/icons/Adwaita", false)
	h.roBind("/usr/share/mime", "/usr/share/mime", false)
	gtkRcPath := filepath.Join(h.homeDir, ".gtkrc-2.0")
	h.setenv("GTK2_RC_FILES", gtkRcPath)
	h.assetFile(gtkRcPath, "gtkrc-2.0")

	pulseAudioWorks := false
	if cfg.Sandbox.EnablePulseAudio {
		if err = h.enablePulseAudio(); err != nil {
			log.Printf("sandbox: failed to proxy PulseAudio: %v", err)
		} else {
			pulseAudioWorks = true
		}
	}
	h.roBind("/usr/share/libthai/thbrk.tri", "/usr/share/libthai/thbrk.tri", true) // Thai language support (Optional).

	browserHome := filepath.Join(h.homeDir, "sandboxed-tor-browser", "tor-browser", "Browser")
	realBrowserHome := filepath.Join(cfg.BundleInstallDir, "Browser")
	realProfileDir := filepath.Join(realBrowserHome, profileSubDir)
	realCachesDir := filepath.Join(realBrowserHome, cachesSubDir)
	realDesktopDir := filepath.Join(realBrowserHome, "Desktop")
	realDownloadsDir := filepath.Join(realBrowserHome, "Downloads")

	// Ensure that the `Downloads` and `Desktop` mount points exist.
	if err = os.MkdirAll(realDesktopDir, DirMode); err != nil {
		return
	}
	if err = os.MkdirAll(realDownloadsDir, DirMode); err != nil {
		return
	}

	// Apply directory overrides.
	if cfg.Sandbox.DesktopDir != "" {
		realDesktopDir = cfg.Sandbox.DesktopDir
	}
	if cfg.Sandbox.DownloadsDir != "" {
		realDownloadsDir = cfg.Sandbox.DownloadsDir
	}

	profileDir := filepath.Join(browserHome, profileSubDir)
	cachesDir := filepath.Join(browserHome, cachesSubDir)
	downloadsDir := filepath.Join(browserHome, "Downloads")
	desktopDir := filepath.Join(browserHome, "Desktop")

	// Filesystem stuff.
	h.roBind(cfg.BundleInstallDir, filepath.Join(h.homeDir, "sandboxed-tor-browser", "tor-browser"), false)
	h.bind(realProfileDir, profileDir, false)
	h.bind(realDesktopDir, desktopDir, false)
	h.bind(realDownloadsDir, downloadsDir, false)
	h.bind(realCachesDir, cachesDir, false) // XXX: Do I need this?
	h.roBind(filepath.Join(realProfileDir, "preferences"), filepath.Join(profileDir, "preferences"), false)
	h.chdir = browserHome
	if !cfg.Sandbox.VolatileExtensionsDir {
		// Unless overridden, the extensions directory should be mounted
		// read-only.
		h.roBind(filepath.Join(realProfileDir, "extensions"), filepath.Join(profileDir, "extensions"), false)
	}

	// Env vars taken from start-tor-browser.
	// h.setenv("LD_LIBRARY_PATH", filepath.Join(browserHome, "TorBrowser", "Tor"))
	h.setenv("LD_LIBRARY_PATH", filepath.Join(browserHome, "TorBrowser", "Tor"))
	h.setenv("FONTCONFIG_PATH", filepath.Join(browserHome, "TorBrowser", "Data", "fontconfig"))
	h.setenv("FONTCONFIG_FILE", "fonts.conf")
	if manif.Channel == "hardened" {
		h.setenv("ASAN_OPTIONS", "detect_leaks=0")
		h.setenv("NSS_DISABLE_HW_AES", "1") // For selfrando.
	}

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

	// Inject the AF_LOCAL compatibility hack stub into the filesystem, and
	// supply the relevant args required for functionality.
	ctrlPath := filepath.Join(h.runtimeDir, controlSocket)
	socksPath := filepath.Join(h.runtimeDir, socksSocket)
	h.setenv("LD_PRELOAD", stubPath)
	h.setenv("TOR_STUB_CONTROL_SOCKET", ctrlPath)
	h.setenv("TOR_STUB_SOCKS_SOCKET", socksPath)
	h.bind(tor.CtrlSurrogatePath(), ctrlPath, false)
	h.bind(tor.SocksSurrogatePath(), socksPath, false)
	h.assetFile(stubPath, "tbb_stub.so")

	// Tor Browser currently is incompatible with PaX MPROTECT, apply the
	// override if needed.
	realFirefoxPath := filepath.Join(realBrowserHome, "firefox")
	if err = applyPaXAttributes(manif, realFirefoxPath); err != nil {
		return nil, err
	}

	extraLdLibraryPath := ""
	if dynlib.IsSupported() {
		cache, err := dynlib.LoadCache()
		if err != nil {
			return nil, err
		}

		// XXX: It's probably safe to assume that firefox will always link
		// against libc and libpthread that are required by `tbb_stub.so`.
		binaries := []string{realFirefoxPath}
		matches, err := filepath.Glob(realBrowserHome + "/*.so")
		if err != nil {
			return nil, err
		}
		binaries = append(binaries, matches...)
		ldLibraryPath := realBrowserHome + ":" + filepath.Join(realBrowserHome, "TorBrowser", "Tor")

		// Extra libraries that firefox dlopen()s.
		extraLdLibraryPath = extraLdLibraryPath + ":" + restrictedLibDir
		extraLibs := []string{
			// These are absolutely required, or libxul.so will crash
			// the firefox process.  Perhapbs wayland will deliver us
			// from this evil.
			"libxcb.so.1",
			"libXau.so.6",
			"libXdmcp.so.6",

			// "libXss.so.1", - Not ubiquitous? nsIdleService uses this.
			// "libc.so", - Uhhhhh.... wtf?
			// "libcanberra.so.0", - Not ubiquitous.
		}
		if cfg.Sandbox.EnablePulseAudio && pulseAudioWorks {
			const libPulse = "libpulse.so.0"

			paLibsPath := findDistributionDependentLibs("", "pulseaudio")
			if paLibsPath != "" && cache.GetLibraryPath(libPulse) != "" {
				const restrictedPulseDir = "/usr/lib/pulseaudio"

				// The library search path ("/usr/lib/pulseaudio"), is
				// hardcoded into libpulse.so.0, because you suck, and we hate
				// you.
				extraLibs = append(extraLibs, libPulse)
				ldLibraryPath = ldLibraryPath + ":" + paLibsPath
				h.roBind(paLibsPath, restrictedPulseDir, false)
				extraLdLibraryPath = extraLdLibraryPath + ":" + restrictedPulseDir
			} else {
				log.Printf("sandbox: Failed to find pulse audio libraries.")
			}
		}
		if codec := findBestCodec(cache); codec != "" {
			extraLibs = append(extraLibs, codec)
		}

		// Gtk uses plugin libraries and shit for theming, and expecting
		// them to be in consistent locations, is too much to ask for.
		gtkExtraLibs, gtkLibPaths, err := h.appendRestrictedGtk2()
		if err != nil {
			return nil, err
		}
		extraLibs = append(extraLibs, gtkExtraLibs...)
		ldLibraryPath = ldLibraryPath + gtkLibPaths

		if err := h.appendLibraries(cache, binaries, extraLibs, ldLibraryPath); err != nil {
			return nil, err
		}
	}
	h.setenv("LD_LIBRARY_PATH", filepath.Join(browserHome, "TorBrowser", "Tor")+extraLdLibraryPath)

	h.cmd = filepath.Join(browserHome, "firefox")
	h.cmdArgs = []string{"--class", "Tor Browser", "-profile", profileDir}

	return h.run()
}

func findBestCodec(cache *dynlib.Cache) string {
	// This needs to be kept in sync with firefox. :(
	codecs := []string{
		"libavcodec-ffmpeg.so.57",
		"libavcodec-ffmpeg.so.56",
		"libavcodec.so.57",
		"libavcodec.so.56",
		"libavcodec.so.55",
		"libavcodec.so.54",
		"libavcodec.so.53",

		// Fairly sure upstream firefox is dropping support for these,
		// and NES emulators considered harmful.
		//
		// "libgstreamer-0.10.so.0",
		// "libgstapp-0.10.so.0",
		// "libgstvideo-0.10.so.0",
	}
	for _, codec := range codecs {
		if cache.GetLibraryPath(codec) != "" {
			return codec
		}
	}
	return ""
}

func applyPaXAttributes(manif *config.Manifest, f string) error {
	const paxAttr = "user.pax.flags"

	sz, _ := syscall.Getxattr(f, paxAttr, nil)

	// Strip off the attribute if this is a non-grsec kernel, or the bundle is
	// sufficiently recent to the point where the required W^X fixes are present
	// in the JIT.
	if !IsGrsecKernel() || manif.BundleVersionAtLeast(7, 0) {
		if sz > 0 {
			log.Printf("sandbox: Removing Tor Browser PaX attributes.")
			syscall.Removexattr(f, paxAttr)
		}
		return nil
	}

	paxOverride := []byte{'m'}
	if sz > 0 {
		dest := make([]byte, sz)
		if _, err := syscall.Getxattr(f, paxAttr, dest); err != nil {
			return err
		}
		if bytes.Contains(dest, paxOverride) {
			log.Printf("sandbox: Tor Browser PaX attributes already set.")
			return nil
		}
	}

	log.Printf("sandbox: Applying Tor Browser PaX attributes.")
	return syscall.Setxattr(f, paxAttr, paxOverride, 0)
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
	logger := newConsoleLogger("update")
	h.stdout = logger
	h.stderr = logger
	h.seccompFn = installTorBrowserSeccompProfile

	// https://wiki.mozilla.org/Software_Update:Manually_Installing_a_MAR_file
	const (
		installDir = "/home/amnesia/sandboxed-tor-browser/tor-browser"
		updateDir  = "/home/amnesia/sandboxed-tor-browser/update"
	)

	browserHome := filepath.Join(h.homeDir, "sandboxed-tor-browser", "tor-browser", "Browser")
	realInstallDir := cfg.BundleInstallDir
	realUpdateDir := filepath.Join(cfg.UserDataDir, "update")
	realUpdateBin := filepath.Join(realInstallDir, "Browser", "updater")

	// Do the work neccecary to make the firefox `updater` happy.
	if err = stageUpdate(realUpdateDir, realInstallDir, mar); err != nil {
		return err
	}

	h.bind(realInstallDir, installDir, false)
	h.bind(realUpdateDir, updateDir, false)
	h.chdir = browserHome // Required (Step 5.)

	extraLdLibraryPath := ""
	if dynlib.IsSupported() {
		cache, err := dynlib.LoadCache()
		if err != nil {
			return err
		}

		if err := h.appendLibraries(cache, []string{realUpdateBin}, nil, filepath.Join(realInstallDir, "Browser")); err != nil {
			return err
		}
		extraLdLibraryPath = extraLdLibraryPath + ":" + restrictedLibDir
	}
	h.setenv("LD_LIBRARY_PATH", browserHome+extraLdLibraryPath)

	// 7. For Firefox 40.x and above run the following from the command prompto
	//    after adding the path to the existing installation directory to the
	//    LD_LIBRARY_PATH environment variable.
	h.cmd = filepath.Join(updateDir, "updater")
	h.cmdArgs = []string{updateDir, browserHome, browserHome}
	cmd, err := h.run()
	if err != nil {
		return err
	}
	cmd.Wait()

	// 8. After the update has completed a file named update.status will be
	//    created in the outside directory.
	status, err := ioutil.ReadFile(filepath.Join(realUpdateDir, "update.status"))
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
	if err := os.MkdirAll(updateDir, DirMode); err != nil {
		return err
	}

	// 2. Copy updater from the application's installation directory that is
	//    to be upgraded into the outside directory. If you would like to
	//    display the updater user interface while it is applying the update
	//    also copy the updater.ini into the outside directory.
	if err := copyFile(filepath.Join(installDir, "Browser", "updater"), filepath.Join(updateDir, "updater")); err != nil {
		return err
	}

	// 3. Download the appropriate .mar file and put it into the outside
	//    directory you created (see Where to get a mar file).
	// 4. Rename the mar file you downloaded to update.mar.
	if err := ioutil.WriteFile(filepath.Join(updateDir, "update.mar"), mar, FileMode); err != nil {
		return err
	}

	return nil
}

// RunTor launches sandboxeed Tor.
func RunTor(cfg *config.Config, torrc []byte) (cmd *exec.Cmd, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	h, err := newHugbox()
	if err != nil {
		return nil, err
	}

	logger := newConsoleLogger("tor")
	h.stdout = logger
	h.stderr = logger
	if !cfg.Tor.UseBridges {
		h.seccompFn = installTorSeccompProfile
	} else {
		h.seccompFn = installBasicSeccompBlacklist
	}
	h.unshare.net = false // Tor needs host network access.

	if err = os.MkdirAll(cfg.TorDataDir, DirMode); err != nil {
		return
	}

	realTorHome := filepath.Join(cfg.BundleInstallDir, "Browser", "TorBrowser", "Tor")
	realTorBin := filepath.Join(realTorHome, "tor")
	realGeoIPDir := filepath.Join(cfg.BundleInstallDir, "Browser", "TorBrowser", "Data", "Tor")
	torDir := filepath.Join(h.homeDir, "tor")
	torBinDir := filepath.Join(torDir, "bin")
	torrcPath := filepath.Join(torDir, "etc", "torrc")

	h.dir(torDir)
	h.roBind(realTorHome, torBinDir, false)
	for _, v := range []string{"geoip", "geoip6"} {
		h.roBind(filepath.Join(realGeoIPDir, v), filepath.Join(torDir, "etc", v), false)
	}
	h.bind(cfg.TorDataDir, filepath.Join(torDir, "data"), false)
	h.file(torrcPath, torrc)

	// If we have the dynamic linker cache available, only load in the
	// libraries that matter.
	extraLdLibraryPath := ""
	if dynlib.IsSupported() {
		cache, err := dynlib.LoadCache()
		if err != nil {
			return nil, err
		}

		// XXX: For now assume that PTs will always use a subset of the tor
		// binaries libraries.
		if err := h.appendLibraries(cache, []string{realTorBin}, nil, realTorHome); err != nil {
			return nil, err
		}
		extraLdLibraryPath = extraLdLibraryPath + ":" + restrictedLibDir
	}
	h.setenv("LD_LIBRARY_PATH", torBinDir+extraLdLibraryPath)

	h.cmd = filepath.Join(torBinDir, "tor")
	h.cmdArgs = []string{"-f", torrcPath}

	return h.run()
}

type consoleLogger struct {
	prefix string
}

func (l *consoleLogger) Write(p []byte) (n int, err error) {
	for _, s := range bytes.Split(p, []byte{'\n'}) {
		if len(s) != 0 { // Trim empty lines.
			log.Printf("%s: %s", l.prefix, s)
		}
	}
	return len(p), nil
}

func newConsoleLogger(prefix string) *consoleLogger {
	l := new(consoleLogger)
	l.prefix = prefix
	return l
}

func findDistributionDependentLibs(subDir, fn string) string {
	for _, base := range distributionDependentLibSearchPath {
		candidate := filepath.Join(base, subDir, fn)
		if FileExists(candidate) {
			return candidate
		}
	}
	return ""
}

func (h *hugbox) appendRestrictedGtk2() ([]string, string, error) {
	const (
		libAdwaita   = "libadwaita.so"
		libPixmap    = "libpixmap.so"
		libPngLoader = "libpixbufloader-png.so"

		gtkSubDir = "gtk-2.0/2.10.0/engines"
		gdkSubDir = "gdk-pixbuf-2.0/2.10.0/loaders"
	)

	gtkLibs := []string{}
	gtkLibPath := ""

	// Figure out where the system keeps the Gtk+-2.0 theme libraries,
	// and bind mount in Adwaita and Pixmap.
	adwaitaPath := findDistributionDependentLibs(gtkSubDir, libAdwaita)
	if adwaitaPath != "" {
		gtkEngineDir, _ := filepath.Split(adwaitaPath)
		normGtkEngineDir := filepath.Join(restrictedLibDir, "gtk-2.0", "2.10.0", "engines")
		h.roBind(adwaitaPath, filepath.Join(normGtkEngineDir, libAdwaita), false)
		h.roBind(filepath.Join(gtkEngineDir, libPixmap), filepath.Join(normGtkEngineDir, libPixmap), true)
		h.setenv("GTK_PATH", filepath.Join(restrictedLibDir, "gtk-2.0"))

		gtkLibs = append(gtkLibs, libAdwaita)
		gtkLibPath = gtkLibPath + ":" + gtkEngineDir
	} else {
		log.Printf("sandbox: Failed to find gtk-2.0 libadwaita.so.")
	}

	// Figure out if the system gdk-pixbuf-2.0 needs loaders for common
	// file formats.  Arch and Fedora 25 do not.  Debian does.  As far as
	// I can tell, the only file format we actually care about is PNG.
	pngLoaderPath := findDistributionDependentLibs(gdkSubDir, libPngLoader)
	if pngLoaderPath != "" {
		loaderDir, _ := filepath.Split(pngLoaderPath)
		normGdkPath := filepath.Join(restrictedLibDir, "gdk-pixbuf-2.0", "2.10.0")
		normPngLoaderPath := filepath.Join(normGdkPath, "loaders", libPngLoader)
		h.roBind(pngLoaderPath, normPngLoaderPath, false)

		// GDK doesn't have a nice equivalent to `GTK_PATH`, and instead has
		// an env var pointing to a `loaders.cache` file.
		loaderCachePath := filepath.Join(normGdkPath, "loaders.cache")
		h.assetFile(loaderCachePath, "loader.cache")
		h.setenv("GDK_PIXBUF_MODULE_FILE", loaderCachePath)

		gtkLibs = append(gtkLibs, libPngLoader)
		gtkLibPath = gtkLibPath + ":" + loaderDir
	}

	return gtkLibs, gtkLibPath, nil
}

func (h *hugbox) appendLibraries(cache *dynlib.Cache, binaries []string, extraLibs []string, ldLibraryPath string) error {
	defer runtime.GC()

	// ld-linux(-x86-64).so needs special handling since it needs to be in
	// a precise location on the filesystem.
	ldSoPath, err := dynlib.FindLdSo()
	ldSoFile := ""
	if err != nil {
		return err
	} else {
		Debugf("sandbox: ld.so appears to be '%v'.", ldSoPath)
		if ldSoFile, err = filepath.EvalSymlinks(ldSoPath); err != nil {
			return err
		}
	}

	toBindMount, err := cache.ResolveLibraries(binaries, extraLibs, ldLibraryPath)
	if err != nil {
		return err
	}

	// XXX: This needs one more de-dup pass to see if the sandbox expects two
	// different versions to share an alias.

	// Ensure that bindMounts happen in a consistent order.
	sortedLibs := []string{}
	for k, _ := range toBindMount {
		sortedLibs = append(sortedLibs, k)
	}
	sort.Strings(sortedLibs)

	// Append all the things!
	for _, realLib := range sortedLibs {
		if realLib == ldSoFile {
			h.roBind(realLib, ldSoPath, false)
			continue
		}

		aliases := toBindMount[realLib]
		Debugf("sandbox: lib: %v", realLib)
		sort.Strings(aliases) // Likewise, ensure symlink ordering.

		// Avoid leaking information about exact library versions to cursory
		// inspection by bind mounting libraries in as the first alias, and
		// then symlinking off that.
		src := filepath.Join(restrictedLibDir, aliases[0])
		h.roBind(realLib, src, false)
		aliases = aliases[1:]
		if len(aliases) == 0 {
			continue
		}

		symlinked := make(map[string]bool) // XXX: Fairly sure this is unneeded.
		for _, alias := range aliases {
			dst := filepath.Join(restrictedLibDir, alias)
			if _, ok := symlinked[dst]; !ok {
				if dst != src {
					h.symlink(src, dst)
					symlinked[dst] = true
				}
			}
		}
	}

	h.standardLibs = false

	return nil
}

func init() {
	searchPaths := []string{
		"/usr/lib", // Arch Linux.
	}
	switch runtime.GOARCH {
	case "amd64":
		searchPaths = append([]string{
			"/usr/lib64",                // Fedora 25
			"/usr/lib/x86_64-linux-gnu", // Debian
		}, searchPaths...)
	case "386":
		searchPaths = append([]string{
			"/usr/lib32",
			"/usr/lib/i386-linux-gnu", // Debian
		}, searchPaths...)
	}

	distributionDependentLibSearchPath = searchPaths
}
