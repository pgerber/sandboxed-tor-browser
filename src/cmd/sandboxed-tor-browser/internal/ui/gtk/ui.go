// ui.go - Gtk+ user interface routines.
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

// Package gtk implements a Gtk+ user interface.
package gtk

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	gtk3 "github.com/gotk3/gotk3/gtk"

	"cmd/sandboxed-tor-browser/internal/data"
	sbui "cmd/sandboxed-tor-browser/internal/ui"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

type errorInvalidBuilderObject struct {
	obj glib.IObject
}

func (e *errorInvalidBuilderObject) Error() string {
	return fmt.Sprintf("unexpected GtkBuilder object: %v", e.obj)
}

func newInvalidBuilderObject(obj glib.IObject) error {
	return &errorInvalidBuilderObject{obj}
}

type gtkUI struct {
	sbui.Common

	logoPixbuf *gdk.Pixbuf
	iconPixbuf *gdk.Pixbuf
	mainWindow *gtk3.Window // Always hidden.

	installDialog  *installDialog
	progressDialog *progressDialog
}

func (ui *gtkUI) Run() error {
	if err := ui.Common.Run(); err != nil {
		ui.bitch("Failed to run common UI: %v", err)
		return err
	}

	if ui.Cfg.NeedsInstall() || ui.ForceInstall {
		for {
			if !ui.installDialog.run() {
				ui.onDestroy()
				return nil
			} else {
				if err := ui.installDialog.onOk(); err != nil {
					if err != sbui.ErrCanceled {
						ui.bitch("Failed to install: %v", err)
						return err
					}
					continue
				}
				ui.ForceInstall = false
				break
			}
		}
	}

	for {
		// XXX: Configuration.

		// Launch
		if err := ui.launch(); err != nil {
			if err != sbui.ErrCanceled {
				ui.bitch("Failed to launch Tor Browser: %v", err)
			}
			continue
		} else {
			// Wait till the sandboxed process finishes.
			return ui.Sandbox.Wait()
		}
	}
}

func (ui *gtkUI) Term() {
	// By the time this is run, we have exited the Gtk+ event loop, so we
	// can assume we have exclusive ownership of the UI state.
	ui.Common.Term()
}

func Init() (sbui.UI, error) {
	var err error

	// Create the UI object and initialize the common state.
	ui := new(gtkUI)
	if err = ui.Init(); err != nil {
		return nil, err
	}

	// Initialize Gtk+.  Past this point, we can use dialog boxes to
	// convey fatal errors.
	gtk3.Init(nil)

	if ui.logoPixbuf, err = ui.pixbufFromAsset("ui/tbb-logo.png"); err != nil {
		return nil, err
	}
	if ui.iconPixbuf, err = ui.pixbufFromAsset("ui/default48.png"); err != nil {
		return nil, err
	}
	if ui.mainWindow, err = gtk3.WindowNew(gtk3.WINDOW_TOPLEVEL); err != nil {
		return nil, err
	}

	// Load the UI.
	if b, err := gtk3.BuilderNew(); err != nil {
		return nil, err
	} else if d, err := data.Asset("ui/gtkui.ui"); err != nil {
		return nil, err
	} else if err = b.AddFromString(string(d)); err != nil {
		return nil, err
	} else {
		// Installation dialog.
		if err := ui.initInstallDialog(b); err != nil {
			return nil, err
		}

		// Configuration dialog.

		// Progress bar dialog.
		if err := ui.initProgressDialog(b); err != nil {
			return nil, err
		}
	}

	return ui, nil
}

func (ui *gtkUI) onDestroy() {
	ui.Cfg.ResetDirty()
}

func (ui *gtkUI) launch() error {
	// If we don't need to update, and would just launch, quash the UI.
	checkUpdate := ui.Cfg.NeedsUpdateCheck()
	squelchUI := !checkUpdate && ui.Cfg.UseSystemTor

	async := sbui.NewAsync()
	if squelchUI {
		async.UpdateProgress = func(s string) {}
		go ui.DoLaunch(async, checkUpdate)
		<-async.Done
	} else {
		ui.progressDialog.setTitle("Launching Tor Browser")
		ui.progressDialog.setText("Initializing startup process...")
		ui.progressDialog.run(async, func() { ui.DoLaunch(async, checkUpdate) })
	}

	return async.Err
}

func (ui *gtkUI) bitch(format string, a ...interface{}) {
	// XXX: Make this nicer with like, an icon and shit.
	md := gtk3.MessageDialogNew(ui.mainWindow, gtk3.DIALOG_MODAL, gtk3.MESSAGE_ERROR, gtk3.BUTTONS_OK, format, a...)
	md.Run()
	md.Hide()
	ui.forceRedraw()
}

func (ui *gtkUI) pixbufFromAsset(asset string) (*gdk.Pixbuf, error) {
	if d, err := data.Asset(asset); err != nil {
		return nil, err
	} else {
		// This is kind of kludgy and terrible, but somewhat unavoidable
		// for now since gotk3 doesn't support loading pixbufs from byte
		// literals yet.  At least this will be used sparingly...
		_, f := path.Split(asset)
		f = path.Join(ui.Cfg.RuntimeDir, f)
		if err = ioutil.WriteFile(f, d, config.FileMode); err != nil {
			return nil, err
		}
		defer os.Remove(f)

		return gdk.PixbufNewFromFile(f)
	}
}

func (ui *gtkUI) forceRedraw() {
	for gtk3.EventsPending() {
		gtk3.MainIteration()
	}
}
