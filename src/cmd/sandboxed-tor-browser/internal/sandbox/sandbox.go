// sandbox.go - Sandbox enviornment.
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
	"io"
	"io/ioutil"
	"log"
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
	actEPerm := seccomp.ActErrno.SetReturnCode(1)
	syscallBlacklist := []string{
		// linux-user-chroot (v0 profile)
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
		// XXX/yawning: The clone restriction breaks bwrap.  c'est la vie.  It
		// looks like Mozilla is considering using user namespaces for the
		// content process sandboxing efforts, so this may need to be enabled.
		"unshare",
		"mount",
		"pivot_root",
		// {SCMP_SYS(clone), &SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)}, // Breaks bwrap.

		// Profiling operations; we expect these to be done by tools from
		// outside the sandbox.  In particular perf has been the source of many
		// CVEs.
		"perf_event_open",
		"ptrace",

		// firejail seccomp_filter_64()
		// mount
		"umount2",
		"kexec_load",
		// ptrace
		"open_by_handle_at",
		"name_to_handle_at",
		"create_module",
		"init_module",
		"finit_module",
		"delete_module",
		"iopl",
		"ioperm",
		"ioprio_set",
		"swapon",
		"swapoff",
		// syslog
		"process_vm_readv",
		"process_vm_writev",
		"sysfs",
		"_sysctl",
		"adjtimex",
		"clock_adjtime",
		"lookup_dcookie",
		// perf_event_open
		"fanotify_init",
		"kcmp",
		"add_key",
		"request_key",
		"keyctl",
		// uselib
		// acct
		// modify_ldt
		// pivot_root
		"io_setup",
		"io_destroy",
		"io_getevents",
		"io_submit",
		"io_cancel",
		"remap_file_pages",
		// mbind
		// get_mempolicy
		// set_mempolicy
		// migrate_pages
		// move_pages
		"vmsplice",
		"chroot",
		"tuxcall",
		"reboot",
		"nfsservctl",
		"get_kernel_syms",
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
		// mounted, and it's not immediately obvious to me how to handle this
		// without something like AppArmor.
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
		"--dir", runtimeDir(),
		"--setenv", "XDG_RUNTIME_DIR", runtimeDir(),

		// X11.
		"--setenv", "DISPLAY", ":0",

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
		ctrlPath := path.Join(runtimeDir(), controlSocket)
		socksPath := path.Join(runtimeDir(), socksSocket)

		bwrapArgs = append(bwrapArgs, []string{
			"--setenv", "LD_PRELOAD", "/tmp/tbb_stub.so",
			"--bind", path.Join(cfg.RuntimeDir(), controlSocket), ctrlPath,
			"--bind", path.Join(cfg.RuntimeDir(), socksSocket), socksPath,
			"--setenv", "TOR_STUB_CONTROL_SOCKET", ctrlPath,
			"--setenv", "TOR_STUB_SOCKS_SOCKET", socksPath,
		}...)
		if err := newFdFile("/tmp/tbb_stub.so", stub); err != nil {
			return nil, err
		}
	}

	// Setup access to X11 in the sandbox.
	xSockArgs, xauth, err := prepareSandboxedX11(cfg)
	if err != nil {
		// Failed to determine the X server socket.
		if xSockArgs == nil {
			return nil, err
		}

		// Failure to proxy auth is non-fatal.
		log.Printf("failed to configure sandboxed x11: %v", err)
	} else if xauth != nil {
		if err := newFdFile("/home/amnesia/.Xauthority", xauth); err != nil {
			return nil, err
		}
		bwrapArgs = append(bwrapArgs, "--setenv", "XAUTHORITY", "/home/amnesia/.Xauthority")
	}
	bwrapArgs = append(bwrapArgs, xSockArgs...)

	// TODO:
	// Setup access to pulseaudio in the sandbox.

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
	if err := os.MkdirAll(realDownloadsDir, os.ModeDir|0700); err != nil { // Make mountpoint before overriding.
		return nil, err
	}
	if cfg.DownloadsDirectory != "" {
		realDownloadsDir = cfg.DownloadsDirectory
	}

	profileDir := path.Join(browserHome, profileSubDir)
	cachesDir := path.Join(browserHome, cachesSubDir)
	downloadsDir := path.Join(browserHome, "Downloads")

	// Setup the bwrap args to repliccate start-tor-browser.
	extraBwrapArgs := []string{
		// Filesystem stuff.
		"--ro-bind", cfg.UserDataDir(), "/home/amnesia/sandboxed-tor-browser",
		"--bind", realProfileDir, profileDir,
		"--bind", realDownloadsDir, downloadsDir, // Optionally allow the user to respecify this.
		"--bind", realCachesDir, cachesDir, // XXX: Do I need this?
		"--chdir", browserHome,

		// Env vars taken from start-tor-browser
		"--setenv", "HOME", browserHome,
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
	if !cfg.Unsafe.VolatileExtensionsDir {
		// Unless overridden, the extensions directory should be mounted
		// read-only.
		extraBwrapArgs = append(extraBwrapArgs, "--ro-bind", path.Join(realProfileDir, "extensions"), path.Join(profileDir, "extensions"))
	}
	cmdPath := path.Join(browserHome, "firefox")
	cmdArgs := []string{"--class", "Tor Browser", "-profile", profileDir}

	// Proxy the SOCKS port into the sandbox.
	socks, err := launchSocksProxy(cfg)
	if err != nil {
		return nil, err
	}

	// Proxy a restricted control port into the sandbox.
	if err := launchCtrlProxy(cfg, socks); err != nil {
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
	trimmedStatus := bytes.TrimSpace(status)
	if !bytes.Equal(trimmedStatus, []byte("succeeded")) {
		return fmt.Errorf("failed to apply update: %v", string(trimmedStatus))
	}

	// Since the update was successful, clean out the "outside" directory.
	os.RemoveAll(realUpdateDir)

	return nil
}
