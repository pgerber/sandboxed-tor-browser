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
	"strings"

	gtk3 "github.com/gotk3/gotk3/gtk"
)

type configDialog struct {
	ui *gtkUI

	dialog *gtk3.Dialog

	// Sandbox config elements.
	pulseAudioBox            *gtk3.Box
	pulseAudioSwitch         *gtk3.Switch
	volatileExtensionsSwitch *gtk3.Switch
	displayBox               *gtk3.Box
	displayEntry             *gtk3.Entry
	downloadsDirBox          *gtk3.Box
	downloadsDirChooser      *gtk3.FileChooserButton
	desktopDirBox            *gtk3.Box
	desktopDirChooser        *gtk3.FileChooserButton
}

func (d *configDialog) reset() {
	const optionalText = "(Optional)"

	// XXX: Hide PulseAudio option if not available.
	forceAdv := false
	d.pulseAudioSwitch.SetActive(d.ui.Cfg.Sandbox.EnablePulseAudio)
	d.volatileExtensionsSwitch.SetActive(d.ui.Cfg.Sandbox.VolatileExtensionsDir)
	if d.ui.Cfg.Sandbox.Display != "" {
		d.displayEntry.SetText(d.ui.Cfg.Sandbox.Display)
	} else {
		d.displayEntry.SetPlaceholderText(optionalText)
	}
	if d.ui.Cfg.Sandbox.DownloadsDir != "" {
		d.downloadsDirChooser.SetCurrentFolder(d.ui.Cfg.Sandbox.DownloadsDir)
		forceAdv = true
	}
	if d.ui.Cfg.Sandbox.DesktopDir != "" {
		d.desktopDirChooser.SetCurrentFolder(d.ui.Cfg.Sandbox.DesktopDir)
		forceAdv = true
	}

	// Hide certain options from the masses, that are probably confusing.
	for _, w := range []*gtk3.Box{d.displayBox, d.downloadsDirBox, d.desktopDirBox} {
		w.SetVisible(d.ui.AdvancedConfig || forceAdv)
	}
}

func (d *configDialog) onOk() error {
	d.ui.Cfg.SetSandboxEnablePulseAudio(d.pulseAudioSwitch.GetActive())
	d.ui.Cfg.SetSandboxVolatileExtensionsDir(d.volatileExtensionsSwitch.GetActive())
	if s, err := d.displayEntry.GetText(); err != nil {
		return err
	} else {
		d.ui.Cfg.SetSandboxDisplay(strings.TrimSpace(s))
	}
	d.ui.Cfg.SetSandboxDownloadsDir(d.downloadsDirChooser.GetFilename())
	d.ui.Cfg.SetSandboxDesktopDir(d.desktopDirChooser.GetFilename())
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
		if d.pulseAudioBox, err = getBox(b, "pulseAudioBox"); err != nil {
			return err
		}
		if d.pulseAudioSwitch, err = getSwitch(b, "pulseAudioSwitch"); err != nil {
			return err
		}
		if d.volatileExtensionsSwitch, err = getSwitch(b, "volatileExtensionsSwitch"); err != nil {
			return err
		}
		if d.displayBox, err = getBox(b, "displayBox"); err != nil {
			return err
		}
		if d.displayEntry, err = getEntry(b, "displayEntry"); err != nil {
			return err
		}
		if d.downloadsDirBox, err = getBox(b, "downloadsDirBox"); err != nil {
			return err
		}
		if d.downloadsDirChooser, err = getFChooser(b, "downloadsDirChooser"); err != nil {
			return err
		}
		if d.desktopDirBox, err = getBox(b, "desktopDirBox"); err != nil {
			return err
		}
		if d.desktopDirChooser, err = getFChooser(b, "desktopDirChooser"); err != nil {
			return err
		}
	}

	ui.configDialog = d
	return nil
}
