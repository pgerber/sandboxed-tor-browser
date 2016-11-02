// pulse.go - PulseAudio related sandbox routines.
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
	"io/ioutil"
	"os"
	"path"
	"strings"

	xdg "github.com/cep21/xdgbasedir"

	"cmd/sandboxed-tor-browser/internal/ui/config"
)

const (
	pulseServer = "PULSE_SERVER"
	pulseCookie = "PULSE_COOKIE"
)

func prepareSandboxedPulseAudio(cfg *config.Config) (string, []byte, error) {
	const unixPrefix = "unix:"

	if !cfg.Sandbox.EnablePulseAudio {
		return "", nil, fmt.Errorf("bug: PulseAudio prepared when not configured")
	}

	// TODO: PulseAudio can optionally store information regarding the location
	// of the socket and the cookie contents as X11 root window properties.

	// The config may be in a pair of enviornment variables, so check those
	// along with the modern default locations.
	serverPath := os.Getenv(pulseServer)
	if serverPath == "" {
		serverPath = path.Join(runtimeDir(), "pulse/native")
	} else if strings.HasPrefix(serverPath, unixPrefix) {
		serverPath = strings.TrimPrefix(serverPath, unixPrefix)
	} else {
		return "", nil, fmt.Errorf("non-local PulseAudio not supported")
	}

	if fi, err := os.Stat(serverPath); err != nil {
		// No pulse Audio socket.
		return "", nil, fmt.Errorf("no PulseAudio socket")
	} else if fi.Mode()&os.ModeSocket == 0 {
		// Not an AF_LOCAL socket.
		return "", nil, fmt.Errorf("PulseAudio socket isn't an AF_LOCAL socket")
	}

	cookiePath := os.Getenv(pulseCookie)
	if cookiePath == "" {
		var err error
		cookiePath, err = xdg.GetConfigFileLocation("pulse/cookie")
		if err != nil {
			// No cookie found, auth is probably disabled.
			return serverPath, nil, nil
		}
	}
	cookie, err := ioutil.ReadFile(cookiePath)
	if err != nil {
		return "", nil, err
	}

	return serverPath, cookie, nil
}
