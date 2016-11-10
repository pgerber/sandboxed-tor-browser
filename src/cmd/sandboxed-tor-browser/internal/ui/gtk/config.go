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
	"fmt"
	"net"
	"strconv"
	"strings"

	gtk3 "github.com/gotk3/gotk3/gtk"

	sbui "cmd/sandboxed-tor-browser/internal/ui"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

type configDialog struct {
	ui *gtkUI

	dialog *gtk3.Dialog

	// Tor config elements.
	torConfigBox      *gtk3.Box
	torProxyToggle    *gtk3.CheckButton
	torProxyConfigBox *gtk3.Box
	torProxyType      *gtk3.ComboBoxText
	torProxyAddress   *gtk3.Entry
	torProxyPort      *gtk3.Entry
	torProxyAuthBox   *gtk3.Box
	torProxyUsername  *gtk3.Entry
	torProxyPassword  *gtk3.Entry

	torBridgeToggle       *gtk3.CheckButton
	torBridgeConfigBox    *gtk3.Box
	torBridgeInternal     *gtk3.RadioButton
	torBridgeInternalBox  *gtk3.Box
	torBridgeInternalType *gtk3.ComboBoxText
	torBridgeCustom       *gtk3.RadioButton
	torBridgeCustomFrame  *gtk3.Frame
	torBridgeCustomEntry  *gtk3.TextView

	defaultTransportIdx int

	torSystemIndicator *gtk3.Box

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

func (d *configDialog) loadFromConfig() {
	// Populate the fields from the config.

	d.torProxyToggle.SetActive(d.ui.Cfg.Tor.UseProxy)
	d.proxyTypeFromCfg()
	if d.ui.Cfg.Tor.ProxyAddress != "" {
		d.torProxyAddress.SetText(d.ui.Cfg.Tor.ProxyAddress)
	}
	if d.ui.Cfg.Tor.ProxyPort != "" {
		d.torProxyPort.SetText(d.ui.Cfg.Tor.ProxyPort)
	}
	if d.ui.Cfg.Tor.ProxyUsername != "" {
		d.torProxyUsername.SetText(d.ui.Cfg.Tor.ProxyUsername)
	}
	if d.ui.Cfg.Tor.ProxyPassword != "" {
		d.torProxyPassword.SetText(d.ui.Cfg.Tor.ProxyPassword)
	}

	d.torBridgeToggle.SetActive(d.ui.Cfg.Tor.UseBridges)
	d.torBridgeInternal.SetActive(!d.ui.Cfg.Tor.UseCustomBridges)
	d.internalBridgeTypeFromCfg()
	d.torBridgeCustom.SetActive(d.ui.Cfg.Tor.UseCustomBridges)
	if buf, err := d.torBridgeCustomEntry.GetBuffer(); err != nil {
		panic(err)
	} else {
		buf.SetText(d.ui.Cfg.Tor.CustomBridges)
	}
	d.onBridgeTypeChanged()

	// Set the sensitivity based on the toggles.
	d.torProxyConfigBox.SetSensitive(d.torProxyToggle.GetActive())
	d.torBridgeConfigBox.SetSensitive(d.torBridgeToggle.GetActive())
	d.torConfigBox.SetSensitive(!d.ui.Cfg.UseSystemTor)
	d.torSystemIndicator.SetVisible(d.ui.Cfg.UseSystemTor)

	// XXX: Hide PulseAudio option if not available.
	forceAdv := false
	d.pulseAudioSwitch.SetActive(d.ui.Cfg.Sandbox.EnablePulseAudio)
	d.volatileExtensionsSwitch.SetActive(d.ui.Cfg.Sandbox.VolatileExtensionsDir)
	if d.ui.Cfg.Sandbox.Display != "" {
		d.displayEntry.SetText(d.ui.Cfg.Sandbox.Display)
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
	// Validate and propagate the UI entries to the config.

	d.ui.Cfg.Tor.SetUseProxy(d.torProxyToggle.GetActive())
	d.ui.Cfg.Tor.SetProxyType(d.torProxyType.GetActiveText())
	if s, err := d.torProxyAddress.GetText(); err != nil {
		return err
	} else if s = strings.TrimSpace(s); s == "" {
		d.ui.Cfg.Tor.SetProxyAddress(s)
	} else if net.ParseIP(s) == nil {
		return fmt.Errorf("Malformed proxy address: '%v'", s)
	} else {
		d.ui.Cfg.Tor.SetProxyAddress(s)
	}
	if s, err := d.torProxyPort.GetText(); err != nil {
		return err
	} else if s = strings.TrimSpace(s); s == "" {
		d.ui.Cfg.Tor.SetProxyPort(s)
	} else if _, err := strconv.ParseUint(s, 10, 16); err != nil {
		return fmt.Errorf("Malformed proxy port: '%v'", s)
	} else {
		d.ui.Cfg.Tor.SetProxyPort(s)
	}
	if s, err := d.torProxyUsername.GetText(); err != nil {
		return err
	} else {
		d.ui.Cfg.Tor.SetProxyUsername(strings.TrimSpace(s))
	}
	if s, err := d.torProxyPassword.GetText(); err != nil {
		return err
	} else {
		d.ui.Cfg.Tor.SetProxyPassword(strings.TrimSpace(s))
	}
	if d.ui.Cfg.Tor.ProxyAddress == "" || d.ui.Cfg.Tor.ProxyPort == "" {
		d.ui.Cfg.Tor.SetUseProxy(false)
	}

	d.ui.Cfg.Tor.SetUseBridges(d.torBridgeToggle.GetActive())
	d.ui.Cfg.Tor.SetInternalBridgeType(d.torBridgeInternalType.GetActiveText())
	d.ui.Cfg.Tor.SetUseCustomBridges(d.torBridgeCustom.GetActive())
	if buf, err := d.torBridgeCustomEntry.GetBuffer(); err != nil {
		return err
	} else if s, err := buf.GetText(buf.GetStartIter(), buf.GetEndIter(), false); err != nil {
		return err
	} else if s, err = sbui.ValidateBridgeLines(s); err != nil {
		return err
	} else {
		d.ui.Cfg.Tor.SetCustomBridges(s)
	}

	d.ui.Cfg.Sandbox.SetEnablePulseAudio(d.pulseAudioSwitch.GetActive())
	d.ui.Cfg.Sandbox.SetVolatileExtensionsDir(d.volatileExtensionsSwitch.GetActive())
	if s, err := d.displayEntry.GetText(); err != nil {
		return err
	} else {
		d.ui.Cfg.Sandbox.SetDisplay(strings.TrimSpace(s))
	}
	d.ui.Cfg.Sandbox.SetDownloadsDir(d.downloadsDirChooser.GetFilename())
	d.ui.Cfg.Sandbox.SetDesktopDir(d.desktopDirChooser.GetFilename())
	return d.ui.Cfg.Sync()
}

func (d *configDialog) run() bool {
	defer func() {
		d.dialog.Hide()
		d.ui.forceRedraw()
	}()

	return d.dialog.Run() == int(gtk3.RESPONSE_OK)
}

func (d *configDialog) proxyTypeFromCfg() {
	id := 0
	for i, v := range config.TorProxyTypes {
		if v == d.ui.Cfg.Tor.ProxyType {
			id = i
			break
		}
	}
	d.torProxyType.SetActive(id)
	d.onProxyTypeChanged()
}

func (d *configDialog) internalBridgeTypeFromCfg() {
	id := d.defaultTransportIdx
	i := 0
	for transport, _ := range sbui.Bridges {
		if transport == d.ui.Cfg.Tor.InternalBridgeType {
			id = i
			break
		}
		i++
	}
	d.torBridgeInternalType.SetActive(id)
}

func (d *configDialog) onProxyTypeChanged() {
	d.torProxyAuthBox.SetSensitive(d.torProxyType.GetActiveText() != "SOCKS 4")
}

func (d *configDialog) onBridgeTypeChanged() {
	isInternal := d.torBridgeInternal.GetActive()
	d.torBridgeInternalBox.SetSensitive(isInternal)
	d.torBridgeCustomFrame.SetSensitive(!isInternal)
	// XXX: Figure out how to make the entry grey on insensitive...
}

func (ui *gtkUI) initConfigDialog(b *gtk3.Builder) error {
	d := new(configDialog)
	d.ui = ui

	obj, err := b.GetObject("configDialog")
	if err != nil {
		return err
	}

	ok := false
	if d.dialog, ok = obj.(*gtk3.Dialog); !ok {
		return newInvalidBuilderObject(obj)
	} else {
		d.dialog.SetDefaultResponse(gtk3.RESPONSE_CANCEL)
		d.dialog.SetIcon(ui.iconPixbuf)
		d.dialog.SetTransientFor(ui.mainWindow)
	}

	if d.torConfigBox, err = getBox(b, "torConfigBox"); err != nil {
		return err
	}
	if d.torSystemIndicator, err = getBox(b, "cfgSystemTorIndicator"); err != nil {
		return err
	}

	// Tor Proxy config elements.
	if d.torProxyToggle, err = getCheckButton(b, "torProxyToggle"); err != nil {
		return err
	} else {
		d.torProxyToggle.Connect("toggled", func() {
			d.torProxyConfigBox.SetSensitive(d.torProxyToggle.GetActive())
		})
	}
	if d.torProxyConfigBox, err = getBox(b, "torProxyConfigBox"); err != nil {
		return err
	}
	if d.torProxyType, err = getComboBoxText(b, "torProxyType"); err != nil {
		return err
	} else {
		for _, v := range config.TorProxyTypes {
			d.torProxyType.AppendText(v)
		}
		d.torProxyType.Connect("changed", func() { d.onProxyTypeChanged() })
	}
	if d.torProxyAddress, err = getEntry(b, "torProxyAddress"); err != nil {
		return err
	}
	if d.torProxyPort, err = getEntry(b, "torProxyPort"); err != nil {
		return err
	}
	if d.torProxyAuthBox, err = getBox(b, "torProxyAuthBox"); err != nil {
		return err
	}
	if d.torProxyUsername, err = getEntry(b, "torProxyUsername"); err != nil {
		return err
	}
	if d.torProxyPassword, err = getEntry(b, "torProxyPassword"); err != nil {
		return err
	}

	// Tor Bridge config elements.
	if d.torBridgeToggle, err = getCheckButton(b, "torBridgeToggle"); err != nil {
		return err
	} else {
		d.torBridgeToggle.Connect("toggled", func() {
			d.torBridgeConfigBox.SetSensitive(d.torBridgeToggle.GetActive())
		})
	}
	if d.torBridgeConfigBox, err = getBox(b, "torBridgeConfigBox"); err != nil {
		return err
	}
	if d.torBridgeInternal, err = getRadioButton(b, "torBridgeInternal"); err != nil {
		return err
	} else {
		d.torBridgeInternal.Connect("toggled", func() { d.onBridgeTypeChanged() })
	}
	if d.torBridgeInternalBox, err = getBox(b, "torBridgeInternalBox"); err != nil {
		return err
	}
	if d.torBridgeInternalType, err = getComboBoxText(b, "torBridgeInternalType"); err != nil {
		return err
	} else {
		i := 0
		for transport, _ := range sbui.Bridges {
			if transport == sbui.DefaultBridgeTransport {
				d.defaultTransportIdx = i
			}
			i++
			d.torBridgeInternalType.AppendText(transport)
		}
	}
	if d.torBridgeCustom, err = getRadioButton(b, "torBridgeCustom"); err != nil {
		return err
	} else {
		d.torBridgeCustom.Connect("toggled", func() { d.onBridgeTypeChanged() })
	}
	if d.torBridgeCustomFrame, err = getFrame(b, "torBridgeCustomFrame"); err != nil {
		return err
	}
	if d.torBridgeCustomEntry, err = getTextView(b, "torBridgeCustomEntry"); err != nil {
		return err
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

	d.loadFromConfig()

	ui.configDialog = d
	return nil
}
