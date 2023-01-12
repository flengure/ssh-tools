package main

import (
	"errors"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/exp/maps"
)

func listSetCmd(name string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s",
		"for i in ", name, "_ipv6 ", name, "_ipv4 ", name, "_mac; ",
		"do nft list set inet fw4 $i; done;",
	)
}
func listDNSCmd(name string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%s",
		"for i in ", name, "_ipv6 ", name, "_ipv4;",
		"do nft list set inet fw4 $i; done;",
		"printf \"%s\n\" ", "\"cat /etc/dnsmasq.d/", name, ".conf\";",
		"cat /etc/dnsmasq.d/", name, ".conf",
	)
}

var arpCmd = func() string {
	var sb strings.Builder
	sb.WriteString("f='%-18s %-17s %-10s\\n'; ")
	sb.WriteString("ip neigh show | ")
	sb.WriteString("awk -v f=\"$f\" 'BEGIN{ ")
	sb.WriteString("printf f, \"-----------------\", \"---------------\", \"---------\";")
	sb.WriteString("printf f, \"Hardware Address\", \"IP Adress\", \"State\";")
	sb.WriteString("printf f, \"-----------------\", \"---------------\", \"---------\"}")
	sb.WriteString("!/FAILED|INCOMPLETE/{printf f, $5, $1, $6}'")
	return sb.String()
}()

func default_view_map() map[string]string {
	m := make(map[string]string)
	m["src_accept"] = listSetCmd("src_accept")
	m["src_reject"] = listSetCmd("src_reject")
	m["dest_accept"] = listDNSCmd("dest_accept")
	m["dest_reject"] = listDNSCmd("dest_reject")
	m["arp table"] = arpCmd
	return m
}

type view_ui struct {
	menu      *widget.Select
	view      *widget.Entry
	status    *widget.Label
	progress  *widget.ProgressBarInfinite
	container *fyne.Container
	conn      conn
	list      map[string]string
	err       error
}

func (ui *view_ui) set_status(s string) {
	if s != "" {
		ui.status.SetText(s)
	}
}

func (ui *view_ui) set_error(s string) {
	ui.err = errors.New(s)
	ui.status.SetText(s)
}

func (ui *view_ui) progress_show(s string) {
	ui.set_status(s)
	ui.progress.Show()
}

func (ui *view_ui) progress_hide(s string) {
	ui.set_status(s)
	ui.progress.Hide()
}

func (ui *view_ui) no_sele() {
	ui.view.Disable()
	ui.progress.Hide()
}

func new_view_ui() *view_ui {

	vm := default_view_map()

	ui := &view_ui{
		menu:     widget.NewSelect(maps.Keys(vm), func(s string) {}),
		view:     widget.NewMultiLineEntry(),
		status:   widget.NewLabel("status..."),
		progress: widget.NewProgressBarInfinite(),
		list:     vm,
		conn:     conn{},
	}

	ui.menu.OnChanged = func(s string) {

		ui.progress_show("Attempting to run remote commands...")

		// No host we probably have no client remember to set this
		if ui.conn.host == "" {
			ui.set_error("host not set, probably no client connection")
			return
		}

		result, err := ui.conn.output(ui.list[s])
		if err != nil {
			ui.err = err
			err_text := fmt.Sprintf("failed: \"%s\"", ui.list[s])
			ui.set_error(err_text)
			ui.progress_hide(err_text)
			ui.view.SetText("")
			ui.view.Disable()
			return
		}

		ui.view.SetText(result)
		ui.view.Enable()
		ui.progress_hide("command ran successfully")

	}

	ui.view.TextStyle = fyne.TextStyle{Monospace: true}
	ui.view.Disable()
	ui.progress.Hidden = true
	ui.status.Hidden = false

	top := container.NewGridWithColumns(3,
		ui.menu, layout.NewSpacer(), layout.NewSpacer())
	bottom := container.NewMax(ui.status, ui.progress)

	ui.container = container.NewBorder(top, bottom, nil, nil, ui.view)

	return ui
}
