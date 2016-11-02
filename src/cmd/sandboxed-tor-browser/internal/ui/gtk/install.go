// install.go - Gtk+ install user interface routines.
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

	sbui "cmd/sandboxed-tor-browser/internal/ui"
)

type installDialog struct {
	ui *gtkUI

	dialog             *gtk3.Dialog
	channelSelector    *gtk3.ComboBoxText
	localeSelector     *gtk3.ComboBoxText
	systemTorIndicator *gtk3.Box
}

func (d *installDialog) run() bool {
	defer d.dialog.Hide()
	return d.dialog.Run() == int(gtk3.RESPONSE_OK)
}

func (d *installDialog) onCancel() {
	d.ui.onDestroy()
}

func (d *installDialog) onOk() error {
	// Reflect the will of the user in the config structure, and write the
	// config to disk.
	d.ui.Cfg.SetChannel(d.channelSelector.GetActiveText())
	d.ui.Cfg.SetLocale(d.localeSelector.GetActiveText())
	if err := d.ui.Cfg.Sync(); err != nil {
		return err
	}

	// No install to be done.
	if !d.ui.Cfg.NeedsInstall() {
		return nil
	}

	// Configure the progress bar dialog.
	d.ui.progressDialog.setTitle("Installing Tor Browser")
	d.ui.progressDialog.setText("Initializing installation process...")

	// Display the progress dialog, and start the install task.
	async := sbui.NewAsync()
	d.ui.progressDialog.run(async, func() { d.ui.DoInstall(async) })
	return async.Err
}

func (d *installDialog) onChannelChanged() {
	// Repopulate the locale dropdown, based on the currently selected locale,
	// for the new channel.
	ch := d.channelSelector.GetActiveText()
	l := d.localeSelector.GetActiveText()
	if l == "" {
		// Use the configured value if there isn't a current sensible selection.
		l = d.ui.Cfg.Locale
	}
	d.localeSelector.RemoveAll()
	id := 0
	for i, v := range sbui.BundleLocales[ch] {
		if v == l {
			id = i
		}
		d.localeSelector.AppendText(v)
	}
	d.localeSelector.SetActive(id)
}

func (ui *gtkUI) initInstallDialog(b *gtk3.Builder) error {
	d := new(installDialog)
	d.ui = ui

	if obj, err := b.GetObject("installDialog"); err != nil {
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

		// Images.
		if obj, err = b.GetObject("installLogo"); err != nil {
			return err
		} else if img, ok := obj.(*gtk3.Image); !ok {
			return err
		} else {
			img.SetFromPixbuf(ui.logoPixbuf)
		}

		// Selectors.
		if obj, err = b.GetObject("channelSelector"); err != nil {
			return err
		} else if d.channelSelector, ok = obj.(*gtk3.ComboBoxText); !ok {
			return newInvalidBuilderObject(obj)
		} else {
			id := 0
			for i, v := range sbui.BundleChannels[ui.Cfg.Architecture] {
				if v == ui.Cfg.Channel {
					id = i
				}
				d.channelSelector.AppendText(v)
			}
			d.channelSelector.SetActive(id)
			d.channelSelector.Connect("changed", func() { d.onChannelChanged() })
		}
		if obj, err = b.GetObject("localeSelector"); err != nil {
			return err
		} else if d.localeSelector, ok = obj.(*gtk3.ComboBoxText); !ok {
			return newInvalidBuilderObject(obj)
		} else {
			// Populate the initial locale dropdown.
			d.onChannelChanged()
		}

		// Indicator.
		if obj, err = b.GetObject("systemTorIndicator"); err != nil {
			return err
		} else if d.systemTorIndicator, ok = obj.(*gtk3.Box); !ok {
			return newInvalidBuilderObject(obj)
		} else {
			d.systemTorIndicator.SetVisible(ui.Cfg.UseSystemTor)
		}
	}

	ui.installDialog = d
	return nil
}
