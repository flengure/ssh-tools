package main

import (
	"errors"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/exp/maps"
)

type emi struct {
	path string
	cmd  string
}

func default_edit_map() map[string]emi {
	m := make(map[string]emi)
	m["src_accept"] = emi{"/etc/firewall/user/src_accept.txt", "fw4 restart"}
	m["src_reject"] = emi{"/etc/firewall/user/src_reject.txt", "fw4 restart"}
	m["dest_accept"] = emi{"/etc/firewall/user/dest_accept.txt", "fw4 restart"}
	m["dest_reject"] = emi{"/etc/firewall/user/dest_reject.txt", "fw4 restart"}
	m["authorized_keys"] = emi{"/etc/dropbear/authorized_keys", ""}
	m["hosts"] = emi{"/etc/hosts", ""}
	return m
}

type edit_ui struct {
	menu      *widget.Select
	save      *widget.Button
	view      *widget.Entry
	status    *widget.Label
	progress  *widget.ProgressBarInfinite
	container *fyne.Container
	conn      conn
	list      map[string]emi
	text      string
	err       error
}

func (ui *edit_ui) set_status(s string) {
	if s != "" {
		ui.status.SetText(s)
	}
}

func (ui *edit_ui) set_error(s string) {
	ui.err = errors.New(s)
	ui.status.SetText(s)
}

func (ui *edit_ui) progress_show(s string) {
	ui.set_status(s)
	ui.progress.Show()
}

func (ui *edit_ui) progress_hide(s string) {
	ui.set_status(s)
	ui.progress.Hide()
}

func new_edit_ui() *edit_ui {

	em := default_edit_map()

	ui := &edit_ui{
		menu:     widget.NewSelect(maps.Keys(em), func(s string) {}),
		save:     widget.NewButton("Save", func() {}),
		view:     widget.NewMultiLineEntry(),
		status:   widget.NewLabel("status..."),
		progress: widget.NewProgressBarInfinite(),
		list:     em,
		conn:     conn{},
	}

	ui.menu.OnChanged = func(s string) {

		var err error

		ui.progress_show("Attempting to load remote file...")

		// No host we probably have no client remember to set this
		if ui.conn.host == "" {
			error_text := "fail: No ssh client"
			ui.set_error(error_text)
			ui.progress_hide(error_text)
			return
		}

		ui.text, err = ui.conn.get_content(ui.list[s].path)
		if err != nil {
			error_text := fmt.Sprintf(
				"fail: scp %s : %s", ui.list[s].path, err.Error())
			ui.set_error(error_text)
			ui.progress_hide(error_text)
			return
		}

		ui.progress_hide(fmt.Sprintf("success: scp %s", ui.list[s].path))

		ui.view.SetText(ui.text)
		ui.view.Enable()
		ui.save.Disable()

	}

	ui.save.OnTapped = func() {

		// var err error

		ui.progress_show("Attempting to save remote file...")

		// No host we probably have no client remember to set this
		if ui.conn.host == "" {
			error_text := "fail: No ssh client"
			ui.set_error(error_text)
			ui.progress_hide(error_text)
			return
		}

		err := ui.conn.set_content(
			ui.view.Text, ui.list[ui.menu.Selected].path)
		if err != nil {
			error_text := "failed: set_content: " + err.Error()
			ui.set_error(error_text)
			ui.progress_hide(error_text)
			return
		}

		ui.text = ui.view.Text

		ui.set_status(fmt.Sprintf(
			"successfully saved \"%s\"", ui.list[ui.menu.Selected].path))

		if ui.list[ui.menu.Selected].cmd != "" {

			// run command associated with saving file
			err = ui.conn.run(ui.list[ui.menu.Selected].cmd)
			if err != nil {
				error_text := fmt.Sprintf(
					"failed running \"%s\"", ui.list[ui.menu.Selected].cmd)
				ui.set_error(error_text)
				ui.progress_hide(error_text)
			}
			ui.progress_hide(fmt.Sprintf(
				"success: saved \"%s\" and ran \"%s\"",
				ui.list[ui.menu.Selected].path,
				ui.list[ui.menu.Selected].cmd,
			))

		}

		ui.progress_hide(fmt.Sprintf(
			"success: saved \"%s\"",
			ui.list[ui.menu.Selected].path,
		))

	}

	ui.view.TextStyle = fyne.TextStyle{Monospace: true}
	ui.view.Disable()
	ui.save.Disable()
	ui.progress.Hidden = true
	ui.status.Hidden = false

	ui.view.OnChanged = func(s string) {
		if s == ui.text {
			ui.save.Disable()
		} else {
			ui.save.Enable()
		}
	}

	top := container.NewGridWithColumns(3,
		ui.menu, layout.NewSpacer(),
		ui.save,
	)
	bottom := container.NewMax(ui.status, ui.progress)
	ui.container = container.NewBorder(top, bottom, nil, nil, ui.view)

	return ui
}
