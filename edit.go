package main

import (
	"fmt"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/ssh"
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

type edit struct {
	menu      *widget.Select
	save      *widget.Button
	view      *widget.Entry
	status    *widget.Label
	progress  *widget.ProgressBarInfinite
	container *fyne.Container
	ssh       *ssh.Client
	list      map[string]emi
	connected string
	text      string
	err       error
}

func (ui *edit) getEdit(s string) {

	ui.progress.Show()

	// No host we probably have no client remember to set this
	if ui.connected == "" {
		ui.status.SetText("No ssh client")
		ui.progress.Hide()
		return
	}

	// open a client connection
	sess, err := ui.ssh.NewSession()
	if err != nil {
		ui.err = err
		ui.status.SetText("Failed to create session")
		ui.progress.Hide()
		return
	}
	defer sess.Close()
	ui.status.SetText("New Session")

	// run cat command
	// cat filename
	// where filename is e.list[s]
	result, err := sess.Output(fmt.Sprintf(
		"cat \"%s\"",
		ui.list[s].path),
	)
	if err != nil {
		ui.err = err
		ui.status.SetText(fmt.Sprintf(
			"failed: cat \"%s\"",
			ui.list[s].path),
		)
		ui.progress.Hide()
		return
	}

	// file was written successfully
	ui.status.SetText(fmt.Sprintf(
		"success: cat \"%s\"",
		ui.list[s].path),
	)
	ui.text = string(result)
	ui.view.SetText(ui.text)
	ui.view.Enable()
	ui.save.Disable()
	ui.progress.Hide()
	// ui.InitContainer()
}

func (ui *edit) saveEdit() {

	ui.progress.Show()

	// No host we probably have no client remember to set this
	if ui.connected == "" {
		ui.status.SetText("No ssh client")
		ui.progress.Hide()
		return
	}

	// open a client connection
	sess1, err := ui.ssh.NewSession()
	if err != nil {
		ui.err = err
		ui.status.SetText("Failed to create session")
		ui.progress.Hide()
		return
	}
	defer sess1.Close()
	ui.status.SetText("New Session")

	// stdin pipe
	w, err := sess1.StdinPipe()
	if err != nil {
		ui.err = err
		ui.status.SetText("unable to open StdinPipe")
		ui.progress.Hide()
		return
	}
	ui.status.SetText("stdinPipe opened successfully")
	defer w.Close()

	// echo to remote file
	err = sess1.Start(fmt.Sprintf(
		"cat > \"%s\"",
		ui.list[ui.menu.Selected].path),
	)
	if err != nil {
		ui.err = err
		ui.status.SetText("unable to stream buffer to remote file")
		ui.progress.Hide()
		return
	}

	// write the textentry contents to the pipe
	i, err := fmt.Fprintf(w, ui.view.Text)
	if err != nil {
		ui.err = err
		ui.status.SetText("could not write to StdinPipe")
		ui.progress.Hide()
		return
	}

	// what do I do with this ?
	fmt.Println(i)

	ui.text = ui.view.Text

	ui.status.SetText(fmt.Sprintf(
		"successfully saved \"%s\"",
		ui.list[ui.menu.Selected].path,
	))

	if ui.list[ui.menu.Selected].cmd != "" {

		// open another client session
		sess2, err := ui.ssh.NewSession()
		if err != nil {
			ui.err = err
			ui.status.SetText("Failed to create session")
			ui.progress.Hide()
			return
		}
		defer sess2.Close()
		ui.status.SetText("New Session")

		sess2.Stdout = os.Stdout
		sess2.Stderr = os.Stderr

		// run command associated with saving file
		err = sess2.Run(ui.list[ui.menu.Selected].cmd)
		if err != nil {
			ui.err = err
			ui.status.SetText(fmt.Sprintf(
				"failed running \"%s\"",
				ui.list[ui.menu.Selected].cmd,
			))
			ui.progress.Hide()
			return
		}
		ui.status.SetText(fmt.Sprintf(
			"successfully saved \"%s\" and ran \"%s\"",
			ui.list[ui.menu.Selected].path,
			ui.list[ui.menu.Selected].cmd,
		))

	}

}

func NewEdit() *edit {

	em := default_edit_map()

	ui := &edit{
		menu:     widget.NewSelect(maps.Keys(em), func(s string) {}),
		save:     widget.NewButton("Save", func() {}),
		view:     widget.NewMultiLineEntry(),
		status:   widget.NewLabel("status..."),
		progress: widget.NewProgressBarInfinite(),
		list:     em,
	}

	ui.menu.OnChanged = func(s string) { ui.getEdit(s) }
	ui.save.OnTapped = func() { ui.saveEdit() }
	ui.view.TextStyle = fyne.TextStyle{Monospace: true}
	ui.view.Disable()
	ui.save.Disable()
	ui.progress.Hidden = true
	ui.status.Hidden = false

	top := container.NewGridWithColumns(
		3,
		ui.menu, layout.NewSpacer(),
		ui.save,
	)
	bottom := container.NewMax(ui.status, ui.progress)
	ui.container = container.NewBorder(top, bottom, nil, nil, ui.view)

	return ui
}