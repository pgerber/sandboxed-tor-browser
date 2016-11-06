// config.go - Gtk+ config user interface routines.
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

package gtk

import (
	gtk3 "github.com/gotk3/gotk3/gtk"
	//sbui "cmd/sandboxed-tor-browser/internal/ui"
)

type configDialog struct {
	ui *gtkUI

	dialog                   *gtk3.Dialog
	pulseAudioSwitch         *gtk3.Switch
	volatileExtensionsSwitch *gtk3.Switch
}

func (d *configDialog) reset() {
	// XXX: Hide PulseAudio option if not available.
	d.pulseAudioSwitch.SetActive(d.ui.Cfg.Sandbox.EnablePulseAudio)
	d.volatileExtensionsSwitch.SetActive(d.ui.Cfg.Sandbox.VolatileExtensionsDir)
}

func (d *configDialog) onOk() error {
	d.ui.Cfg.SetSandboxEnablePulseAudio(d.pulseAudioSwitch.GetActive())
	d.ui.Cfg.SetSandboxVolatileExtensionsDir(d.volatileExtensionsSwitch.GetActive())

	return d.ui.Cfg.Sync()
}

func (d *configDialog) run() bool {
	d.reset()
	defer func() {
		d.dialog.Hide()
		d.ui.forceRedraw()
	}()

	return d.dialog.Run() == int(gtk3.RESPONSE_OK)
}

func (ui *gtkUI) initConfigDialog(b *gtk3.Builder) error {
	d := new(configDialog)
	d.ui = ui

	if obj, err := b.GetObject("configDialog"); err != nil {
		return err
	} else {
		ok := false
		if d.dialog, ok = obj.(*gtk3.Dialog); !ok {
			return newInvalidBuilderObject(obj)
		} else {
			d.dialog.SetDefaultResponse(gtk3.RESPONSE_CANCEL)
			d.dialog.SetIcon(ui.iconPixbuf)
			d.dialog.SetTransientFor(ui.mainWindow)
		}

		// Sandbox config elements.
		if obj, err = b.GetObject("pulseAudioSwitch"); err != nil {
			return err
		} else if d.pulseAudioSwitch, ok = obj.(*gtk3.Switch); !ok {
			return newInvalidBuilderObject(obj)
		}
		if obj, err = b.GetObject("volatileExtensionsSwitch"); err != nil {
			return err
		} else if d.volatileExtensionsSwitch, ok = obj.(*gtk3.Switch); !ok {
			return newInvalidBuilderObject(obj)
		}
	}

	// Apply the configured values.
	d.reset()
	ui.configDialog = d

	return nil
}
