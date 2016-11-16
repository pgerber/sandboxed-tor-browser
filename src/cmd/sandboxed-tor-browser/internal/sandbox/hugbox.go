// hugbox.go - Sandbox enviornment.
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

package sandbox

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"syscall"

	"cmd/sandboxed-tor-browser/internal/data"
)

const sandboxHostname = "amnesia"

type unshareOpts struct {
	user   bool
	ipc    bool
	pid    bool
	net    bool
	uts    bool
	cgroup bool
}

func (u *unshareOpts) toArgs() []string {
	var args []string
	if u.user {
		args = append(args, "--unshare-user-try")
	}
	if u.ipc {
		args = append(args, "--unshare-ipc")
	}
	if u.pid {
		args = append(args, "--unshare-pid")
	}
	if u.net {
		args = append(args, "--unshare-net")
	}
	if u.uts {
		args = append(args, "--unshare-uts")
	}
	if u.cgroup {
		args = append(args, "--unshare-cgroup-try")
	}
	return args
}

type hugbox struct {
	cmd     string
	cmdArgs []string

	hostname   string
	runtimeDir string
	homeDir    string
	chdir      string
	mountProc  bool
	unshare    unshareOpts
	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	seccompFn  func(*os.File) error
	pdeathSig  syscall.Signal

	// Internal options, not to be modified except via helpers, unless you
	// know what you are doing.
	bwrapPath string
	args      []string
	fileData  [][]byte
}

func (h *hugbox) setenv(k, v string) {
	h.args = append(h.args, "--setenv", k, v)
}

func (h *hugbox) dir(dest string) {
	h.args = append(h.args, "--dir", dest)
}

func (h *hugbox) symlink(src, dest string) {
	h.args = append(h.args, "--symlink", src, dest)
}

func (h *hugbox) bind(src, dest string, optional bool) {
	if !fileExists(src) {
		if !optional {
			panic(fmt.Errorf("sandbox: bind source does not exist: %v", src))
		}
		return
	}
	h.args = append(h.args, "--bind", src, dest)
}

func (h *hugbox) roBind(src, dest string, optional bool) {
	if !fileExists(src) {
		if !optional {
			panic(fmt.Errorf("sandbox: roBind source does not exist: %v", src))
		}
		return
	}
	h.args = append(h.args, "--ro-bind", src, dest)
}

func (h *hugbox) file(dest string, data []byte) {
	h.args = append(h.args, "--file", fmt.Sprintf("%d", 4+len(h.fileData)), dest)
	h.fileData = append(h.fileData, data)
}

func (h *hugbox) assetFile(dest, asset string) {
	b, err := data.Asset(asset)
	if err != nil {
		panic(err)
	}
	h.file(dest, b)
}

func (h *hugbox) run() (*exec.Cmd, error) {
	// Create the command struct for the sandbox.
	cmd := &exec.Cmd{
		Path:   h.bwrapPath,
		Args:   []string{h.bwrapPath, "--args", "3", h.cmd},
		Env:    []string{},
		Stdin:  h.stdin,
		Stdout: h.stdout,
		Stderr: h.stderr,
		SysProcAttr: &syscall.SysProcAttr{
			Pdeathsig: h.pdeathSig,
		},
	}
	cmd.Args = append(cmd.Args, h.cmdArgs...)

	defer func() {
		// Force close the unwritten pipe fd(s), on the off-chance that
		// something failed before they could be written.
		for _, f := range cmd.ExtraFiles {
			f.Close()
		}
	}()

	// Prep the args pipe.
	var argsWrFd *os.File
	if r, w, err := os.Pipe(); err != nil {
		return nil, err
	} else {
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		argsWrFd = w
	}

	// Build up the args to be passed via fd.  This specifies args directly
	// instead of using accessors since not everything is exposed, and
	// bubblewrap will fail if the assumptions I need to make about the
	// host system are false.
	fdArgs := []string{
		// Standard things required by most applications.
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--ro-bind", "/usr/lib", "/usr/lib",
		"--ro-bind", "/lib", "/lib",

		"--setenv", "XDG_RUNTIME_DIR", h.runtimeDir,
		"--dir", h.runtimeDir,

		"--setenv", "HOME", h.homeDir,
		"--dir", h.homeDir,
	}
	if runtime.GOARCH == "amd64" { // 64 bit Linux-ism.
		fdArgs = append(fdArgs, "--ro-bind", "/lib64", "/lib64")
	}
	fdArgs = append(fdArgs, h.unshare.toArgs()...) // unshare(2) options.
	if h.hostname != "" {
		if !h.unshare.uts {
			return nil, fmt.Errorf("sandbox: hostname set, without new UTS namespace")
		}
		fdArgs = append(fdArgs, "--hostname", h.hostname)
	}
	if h.mountProc {
		fdArgs = append(fdArgs, "--proc", "/proc")
	}
	if h.chdir != "" {
		fdArgs = append(fdArgs, "--chdir", h.chdir)
	}
	passwdBody := fmt.Sprintf("amnesia:x:%d:%d:Debian Live User,,,:/home/amnesia:/bin/bash\n", os.Getuid(), os.Getgid())
	groupBody := fmt.Sprintf("amnesia:%d:1000\n", os.Getgid())
	h.file("/etc/passwd", []byte(passwdBody))
	h.file("/etc/group", []byte(groupBody))

	// Handle the files to be injected via pipes.
	pendingWriteFds := []*os.File{argsWrFd}
	for i := 0; i < len(h.fileData); i++ {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		pendingWriteFds = append(pendingWriteFds, w)
	}

	// Prep the seccomp pipe if required.
	var seccompWrFd *os.File
	if h.seccompFn != nil {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		// The `-1` is because the args fd is added at this point...
		fdArgs = append(fdArgs, "--seccomp", fmt.Sprintf("%d", 4+len(cmd.ExtraFiles)-1))
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		seccompWrFd = w
	}

	// Convert the arg vector to a format fit for bubblewrap, and schedule the
	// write.
	fdArgs = append(fdArgs, h.args...) // Finalize args.
	var argsBuf []byte
	for _, arg := range fdArgs {
		argsBuf = append(argsBuf, []byte(arg)...)
		argsBuf = append(argsBuf, 0x00)
	}
	pendingWrites := [][]byte{argsBuf}
	pendingWrites = append(pendingWrites, h.fileData...)

	// Fork/exec.
	cmd.Start()

	// Flush the pending writes.
	for i, wrFd := range pendingWriteFds {
		d := pendingWrites[i]
		if err := writeBuffer(wrFd, d); err != nil {
			cmd.Process.Kill()
			return nil, err
		}
		cmd.ExtraFiles = cmd.ExtraFiles[1:]
	}

	// Write the seccomp rules.
	if h.seccompFn != nil {
		// This should be the one and only remaining extra file.
		if len(cmd.ExtraFiles) != 1 {
			panic("sandbox: unexpected extra files when writing seccomp rules")
		} else if seccompWrFd == nil {
			panic("sandbox: missing fd when writing seccomp rules")
		}
		if err := h.seccompFn(seccompWrFd); err != nil {
			cmd.Process.Kill()
			return nil, err
		}
		cmd.ExtraFiles = nil
	} else if seccompWrFd != nil {
		panic("sandbox: seccomp fd exists when there are no rules to be written")
	}

	return cmd, nil
}

func newHugbox() (*hugbox, error) {
	h := &hugbox{
		unshare: unshareOpts{
			user:   true,
			ipc:    true,
			pid:    true,
			net:    true,
			uts:    true,
			cgroup: true,
		},
		hostname:   sandboxHostname,
		mountProc:  true,
		runtimeDir: path.Join("/run", "user", fmt.Sprintf("%d", os.Getuid())),
		homeDir:    "/home/amnesia",
		pdeathSig:  syscall.SIGTERM,
	}

	// Look for the bwrap binary in sensible locations.
	bwrapPaths := []string{
		"/usr/bin/bwrap",
		"/usr/lib/flatpak/flatpak-bwrap", // Arch Linux "flatpak" package.
	}
	for _, v := range bwrapPaths {
		if fileExists(v) {
			h.bwrapPath = v
			break
		}
	}
	if h.bwrapPath == "" {
		return nil, fmt.Errorf("sandbox: unable to find bubblewrap binary")
	}

	return h, nil
}

func fileExists(f string) bool {
	if _, err := os.Lstat(f); err != nil && os.IsNotExist(err) {
		// This might be an EPERM, but bubblewrap can have elevated privs,
		// so this may succeed.  If it doesn't, the error will be caught
		// later.
		return false
	}
	return true
}

func writeBuffer(w io.WriteCloser, contents []byte) error {
	defer w.Close()
	_, err := w.Write(contents)
	return err
}

// IsGrsecKernel returns true if the system appears to be running a grsec
// kernel.
func IsGrsecKernel() bool {
	return fileExists("/proc/sys/kernel/grsecurity") || fileExists("/dev/grsec")
}
