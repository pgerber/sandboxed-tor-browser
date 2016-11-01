// progress.go - Gtk+ progress dialog user interface routines.
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
	sbui "cmd/sandboxed-tor-browser/internal/ui"
	"github.com/gotk3/gotk3/glib"
	gtk3 "github.com/gotk3/gotk3/gtk"
)

type progressDialog struct {
	ui *gtkUI

	dialog       *gtk3.Dialog
	progressText *gtk3.Label

	updateCh chan string
}

func (d *progressDialog) setTitle(s string) {
	d.dialog.SetTitle(s)
}

func (d *progressDialog) setText(s string) {
	d.progressText.SetText(s)
}

func (d *progressDialog) run(async *sbui.Async, runFn func()) {
	const updateInterval = 100 // ms
	cancel := false

	d.updateCh = make(chan string, 2) // HACKHACKHACKHACK
	async.UpdateProgress = func(s string) { d.updateCh <- s }

	var timeoutFn func() bool
	timeoutFn = func() bool {
		if cancel {
			return false
		}

		select {
		case s := <-d.updateCh:
			d.setText(s)
		case <-async.Done:
			if async.Err == nil {
				d.emitOk()
			} else {
				cancel = true
				d.emitCancel()
			}
			return false
		default:
		}

		// BUG: Returning true should re-add the timer, but it doesn't.
		glib.TimeoutAdd(updateInterval, timeoutFn)
		return false
	}
	glib.TimeoutAdd(updateInterval, timeoutFn)

	go runFn()

	defer d.dialog.Hide()
	if d.dialog.Run() != int(gtk3.RESPONSE_OK) {
		if !cancel {
			async.Lock()
			defer async.Unlock()
			cancel = true
			async.Cancel <- true
			<-async.Done
		}
	}
}

func (d *progressDialog) emitOk() {
	d.dialog.Response(gtk3.RESPONSE_OK)
}

func (d *progressDialog) emitCancel() {
	d.dialog.Response(gtk3.RESPONSE_CANCEL)
}

func (ui *gtkUI) initProgressDialog(b *gtk3.Builder) error {
	d := new(progressDialog)
	d.ui = ui

	if obj, err := b.GetObject("progressDialog"); err != nil {
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
		if obj, err = b.GetObject("progressIcon"); err != nil {
			return err
		} else if img, ok := obj.(*gtk3.Image); !ok {
			return err
		} else {
			img.SetFromPixbuf(ui.iconPixbuf)
		}

		// Labels.
		if obj, err = b.GetObject("progressText"); err != nil {
			return err
		} else if d.progressText, ok = obj.(*gtk3.Label); !ok {
			return err
		}
	}

	ui.progressDialog = d
	return nil
}
