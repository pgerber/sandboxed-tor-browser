// sandbox.go - Sandbox enviornment.
// Copyright (C) 2016  Yawning Angel.
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/.

// Package sandbox handles launching applications in a sandboxed enviornment
// via bubblwrap.
package sandbox

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"runtime"
	"syscall"

	seccomp "github.com/seccomp/libseccomp-golang"

	"cmd/sandboxed-tor-browser/internal/config"
)

const (
	sandboxedHostname = "amnesia"
	controlSocket     = "control"
	socksSocket       = "socks"

	browserHome = "/home/amnesia/sandboxed-tor-browser/tor-browser/Browser"
)

func runtimeDir() string {
	return path.Join("/run/user", fmt.Sprintf("%d", os.Getuid()))
}

func installSeccompRules(fd *os.File) error {
	defer fd.Close()

	f, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return err
	}
	defer f.Release()
	if err := f.AddArch(seccomp.ArchNative); err != nil {
		return err
	}

	// Deny access to a bunch of syscalls that have no business being executed.
	//
	// List originally based off the linux-user-chroot v0 profile, which in
	// turn appears to have stolen it from elsewhere.  Yes this can be improved,
	// no I don't think it'll really help unless there's kernel bugs.
	actEPerm := seccomp.ActErrno.SetReturnCode(1)
	syscallBlacklist := []string{
		"syslog",      // Block dmesg
		"uselib",      // Useless old syscall
		"personality", // Don't allow you to switch to bsd emulation or whatnot
		"acct",        // Don't allow disabling accounting
		"modify_ldt",  // 16-bit code is unnecessary in the sandbox, and modify_ldt is a historic source of interesting information leaks.
		"quotactl",    // Don't allow reading current quota use

		// Scary VM/NUMA ops:
		"move_pages",
		"mbind",
		"get_mempolicy",
		"set_mempolicy",
		"migrate_pages",

		// Don't allow subnamespace setups:
		// XXX/yawning: The clone restriction breaks bwrap.  c'est la vie.
		"unshare",
		"mount",
		"pivot_root",
		// {SCMP_SYS(clone), &SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)}, // Breaks bwrap.

		// Profiling operations; we expect these to be done by tools from
		// outside the sandbox.  In particular perf has been the source of many
		// CVEs.
		"perf_event_open",
		"ptrace",

		// Extra stuff not in the linux-user-chroot list.
		"_sysctl", // Use discouraged, the command grovels through proc anyway.
	}
	for _, n := range syscallBlacklist {
		s, err := seccomp.GetSyscallFromName(n)
		if err != nil {
			return err
		}
		if err := f.AddRule(s, actEPerm); err != nil {
			return err
		}
	}

	// Compile the filter rules, and write it out to the bwrap child process.
	return f.ExportBPF(fd)
}

func writeBuffer(w io.WriteCloser, contents []byte) error {
	defer w.Close()
	_, err := w.Write(contents)
	return err
}

func run(cfg *config.Config, cmdPath string, cmdArgs []string, extraBwrapArgs []string, injectStub bool) (*exec.Cmd, error) {
	fdIdx := 4 // Skip stdin, stdout, stderr, and the arg fds.
	type fileWritersFn func() error
	var fileWriters []fileWritersFn

	// XXX: Maybe use pipes for stdout/err and route it to the log.
	cmd := &exec.Cmd{
		Path:       "/usr/bin/bwrap",
		Args:       []string{"/usr/bin/bwrap", "--args", "3", cmdPath},
		Env:        make([]string, 0),
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		ExtraFiles: make([]*os.File, 0),
		SysProcAttr: &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGTERM,
		},
	}
	cmd.Args = append(cmd.Args, cmdArgs...)

	bwrapArgs := []string{
		// Unshare absolutely everything possible.
		"--unshare-ipc",
		"--unshare-pid",
		"--unshare-net",
		"--unshare-uts",
		"--unshare-cgroup",

		// Standard directories required out of any functional U*IX system.
		//
		// XXX: /proc is a shitfest.  Firefox crashes out without /proc
		// mounted, fairly eary since it expects `proc/self` to be
		// readable, but this needs to be investigated further, since if it's
		// the only call that requires access to proc, it'll be easy to fake
		// out the specific check that fails.
		"--tmpfs", "/tmp",
		"--proc", "/proc",
		"--dev", "/dev",
		"--ro-bind", "/usr/lib", "/usr/lib", // /lib -> /usr/lib on my system.
		"--ro-bind", "/lib", "/lib",

		// Make the sandbox look vaguely like Tails.
		"--hostname", sandboxedHostname, // Requires bubblewrap 0.1.2 or later.
		"--dir", "/home/amnesia",
		"--setenv", "HOME", "/home/amnesia",

		// XDG_RUNTIME_DIR.
		"--bind", cfg.RuntimeDir(), runtimeDir(),
		"--setenv", "XDG_RUNTIME_DIR", runtimeDir(),

		// X11. TODO: Improve the way I do this.
		"--bind", "/tmp/.X11-unix", "/tmp/.X11-unix",
		"--setenv", "DISPLAY", os.Getenv("DISPLAY"),

		// The UI looks like total shit without these.  When Tor Browser
		// moves to Gtk-3.0 this will need to be revised.
		"--ro-bind", "/usr/share/gtk-2.0", "/usr/share/gtk-2.0",
		"--ro-bind", "/usr/share/themes", "/usr/share/themes",
		"--ro-bind", "/usr/share/icons", "/usr/share/icons",
	}

	// Append architecture specific directories.
	if runtime.GOARCH == "amd64" {
		bwrapArgs = append(bwrapArgs, "--ro-bind", "/lib64", "/lib64")
	}

	// The main bwrap arguments and a number of files are passed via fds
	// inherited when the fork/exec happens.
	newSandboxedPipe := func(name string) (*os.File, error) {
		if r, w, err := os.Pipe(); err != nil {
			return nil, err
		} else {
			cmd.ExtraFiles = append(cmd.ExtraFiles, r)
			return w, nil
		}
	}
	newFdFile := func(name string, contents []byte) error {
		w, err := newSandboxedPipe(name)
		if err != nil {
			return err
		}
		bwrapArgs = append(bwrapArgs, "--file", fmt.Sprintf("%d", fdIdx), name)
		fdIdx++
		fileWriters = append(fileWriters, func() error { return writeBuffer(w, contents) })
		return nil
	}

	// child fd 3: pass the bwrap arguments.
	argsW, err := newSandboxedPipe("args")
	if err != nil {
		return nil, err
	}

	// The /etc/passwd and /etc/group should be valid so that certain things
	// work, so stick synthetic ones inside the sandbox, with the user/group
	// normalized to resemble that of the Tails amnesia user.
	passwdBody := fmt.Sprintf("amnesia:x:%d:%d:Debian Live User,,,:/home/amnesia:/bin/bash\n", os.Getuid(), os.Getgid())
	groupBody := fmt.Sprintf("amnesia:%d:1000\n", os.Getgid)
	if err := newFdFile("/etc/passwd", []byte(passwdBody)); err != nil {
		return nil, err
	}
	if err := newFdFile("/etc/group", []byte(groupBody)); err != nil {
		return nil, err
	}

	// Inject the AF_LOCAL compatibility hack stub into the filesystem, and
	// append the relevant args required for functionality.
	if injectStub {
		bwrapArgs = append(bwrapArgs, []string{
			"--setenv", "LD_PRELOAD", "/tmp/tbb_stub.so",
			"--setenv", "TOR_CONTROL_SOCKET", path.Join(runtimeDir(), controlSocket),
			"--setenv", "TOR_SOCKS_SOCKET", path.Join(runtimeDir(), socksSocket),
		}...)
		if err := newFdFile("/tmp/tbb_stub.so", stub); err != nil {
			return nil, err
		}
	}

	// Setup access to X11 in the sandbox.
	//
	// While all of the sockets are exposed, only one Xauthority entry is
	// copied into the sancbox.  Whatever, X11 is the weakest link and this
	// shit should use Wayland anyway.
	if xauth, err := prepareSandboxedX11(cfg); err != nil {
		return nil, err
	} else if err := newFdFile("/home/amnesia/.Xauthority", xauth); err != nil {
		return nil, err
	}

	// TODO:
	// Setup access to DRI in the sandbox.
	// Setup access to pulseaudio in the sandbox.

	// Add the extra files.

	// Create the fd used to pass seccomp arguments.
	seccompW, err := newSandboxedPipe("seccomp")
	if err != nil {
		return nil, err
	}
	bwrapArgs = append(bwrapArgs, "--seccomp", fmt.Sprintf("%d", fdIdx))

	// Kick off the child process.
	cmd.Start()

	// Finalize the arguments to be written out via the fd.
	bwrapArgs = append(bwrapArgs, extraBwrapArgs...)

	var bwrapArgsBuf []byte
	for _, arg := range bwrapArgs {
		bwrapArgsBuf = append(bwrapArgsBuf, []byte(arg)...)
		bwrapArgsBuf = append(bwrapArgsBuf, 0x00) // Separated by NUL.
	}
	fileWriters = append([]fileWritersFn{func() error { return writeBuffer(argsW, bwrapArgsBuf) }}, fileWriters...)

	// Write out all of the data to the various fds, in order that they were
	// specified, starting with the arguments.
	for _, wrFn := range fileWriters {
		if err := wrFn(); err != nil {
			cmd.Process.Kill()
			return nil, err
		}
	}

	// Write out the seccomp rules.
	if err := installSeccompRules(seccompW); err != nil {
		cmd.Process.Kill()
		return nil, err
	}

	return cmd, nil
}

func RunTorBrowser(cfg *config.Config) (*exec.Cmd, error) {
	const (
		profileSubDir = "TorBrowser/Data/Browser/profile.default"
		cachesSubDir  = "TorBrowser/Data/Browser/Caches"
	)

	realBrowserHome := path.Join(cfg.UserDataDir(), "tor-browser/Browser")
	realProfileDir := path.Join(realBrowserHome, profileSubDir)
	realCachesDir := path.Join(realBrowserHome, cachesSubDir)
	realDownloadsDir := path.Join(realBrowserHome, "Downloads")

	profileDir := path.Join(browserHome, profileSubDir)
	cachesDir := path.Join(browserHome, cachesSubDir)
	downloadsDir := path.Join(browserHome, "Downloads")

	// Ensure the `Downlaods` directory exists.
	if err := os.MkdirAll(realDownloadsDir, os.ModeDir|0700); err != nil {
		return nil, err
	}

	// Setup the bwrap args to repliccate start-tor-browser.
	extraBwrapArgs := []string{
		// Filesystem stuff.
		"--ro-bind", cfg.UserDataDir(), "/home/amnesia/sandboxed-tor-browser",
		"--bind", realProfileDir, profileDir,
		"--ro-bind", path.Join(realProfileDir, "extensions"), path.Join(profileDir, "extensions"),
		"--bind", realDownloadsDir, downloadsDir, // Optionally allow the user to respecify this.
		"--bind", realCachesDir, cachesDir, // XXX: Do I need this?
		"--chdir", browserHome,

		// Env vars taken from start-tor-browser
		"--setenv", "LD_LIBRARY_PATH", browserHome,
		"--setenv", "FONTCONFIG_PATH", path.Join(browserHome, "TorBrowser/Data/fontconfig"),
		"--setenv", "FONTCONFIG_FILE", "fonts.conf",
		"--setenv", "ASAN_OPTIONS", "detect_leaks=0", // For hardened.

		// This assumes a system Tor instance is in use, because tor-launcher
		// would be started inside the sandbox, unable to access the net.
		"--setenv", "TOR_SOCKS_PORT", "9150",
		"--setenv", "TOR_CONTROLPORT", "9151",
		"--setenv", "TOR_SKIP_LAUNCH", "1",
		"--setenv", "TOR_NO_DISPLAY_NETWORK_SETTINGS", "1",
	}
	cmdPath := path.Join(browserHome, "firefox")
	cmdArgs := []string{"--class", "Tor Browser", "-profile", profileDir}

	// Proxy a restricted control port into the sandbox.
	if err := launchCtrlProxy(cfg); err != nil {
		return nil, err
	}

	// Proxy the SOCKS port into the sandbox.
	if err := launchSocksProxy(cfg); err != nil {
		return nil, err
	}

	return run(cfg, cmdPath, cmdArgs, extraBwrapArgs, true)
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
	if err := copyFile(path.Join(installDir, "Browser", "updater.ini"), path.Join(updateDir, "updater.ini")); err != nil {
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

func RunUpdate(cfg *config.Config, mar []byte) error {
	// https://wiki.mozilla.org/Software_Update:Manually_Installing_a_MAR_file

	const (
		installDir = "/home/amnesia/sandboxed-tor-browser/tor-browser"
		updateDir  = "/home/amnesia/sandboxed-tor-browser/update"
	)
	realInstallDir := path.Join(cfg.UserDataDir(), "tor-browser")
	realUpdateDir := path.Join(cfg.UserDataDir(), "update")

	// Setup the bwrap args for `updater`.
	extraBwrapArgs := []string{
		// Filesystem stuff.
		"--bind", realInstallDir, installDir,
		"--bind", realUpdateDir, updateDir,
		"--chdir", browserHome, // Required (Step 5.)

		"--setenv", "LD_LIBRARY_PATH", browserHome,
		"--setenv", "FONTCONFIG_PATH", path.Join(browserHome, "TorBrowser/Data/fontconfig"),
		"--setenv", "FONTCONFIG_FILE", "fonts.conf",
	}

	// Do the work neccecary to make the firefox `updater` happy.
	if err := stageUpdate(realUpdateDir, realInstallDir, mar); err != nil {
		return err
	}

	// 7. For Firefox 40.x and above run the following from the command prompto
	//    after adding the path to the existing installation directory to the
	//    LD_LIBRARY_PATH environment variable.
	cmdPath := path.Join(updateDir, "updater")
	cmdArgs := []string{updateDir, browserHome, browserHome}
	cmd, err := run(cfg, cmdPath, cmdArgs, extraBwrapArgs, false)
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
	if !bytes.Equal(bytes.TrimSpace(status), []byte("succeeded")) {
		return fmt.Errorf("failed to apply update: %v", string(status))
	}

	// Since the update was successful, clean out the "outside" directory.
	os.RemoveAll(realUpdateDir)

	return nil
}
