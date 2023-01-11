package main

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/ssh"
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

var view_list = view_items{
	{"src_accept", listSetCmd("src_accept")},
	{"src_reject", listSetCmd("src_reject")},
	{"dest_accept", listDNSCmd("dest_accept")},
	{"dest_reject", listDNSCmd("dest_reject")},
	{"arp table", arpCmd},
}

func default_view_map() map[string]string {
	m := make(map[string]string)
	m["src_accept"] = listSetCmd("src_accept")
	m["src_reject"] = listSetCmd("src_reject")
	m["dest_accept"] = listDNSCmd("dest_accept")
	m["dest_reject"] = listDNSCmd("dest_reject")
	m["arp table"] = arpCmd
	return m
}

type view struct {
	menu      *widget.Select
	view      *widget.Entry
	status    *widget.Label
	progress  *widget.ProgressBarInfinite
	container *fyne.Container
	ssh       *ssh.Client
	list      map[string]string
	text      string
	err       error
	connected string
}

func (ui *view) getView(s string) {

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
	result, err := sess.Output(ui.list[s])
	if err != nil {
		ui.err = err
		ui.status.SetText(fmt.Sprintf(
			"failed: \"%s\"",
			ui.list[s]),
		)
		ui.progress.Hide()
		return
	}

	// command was successfully execute
	ui.status.SetText(fmt.Sprintf("success: \"%s\"", s))
	ui.text = string(result)
	ui.view.SetText(ui.text)
	ui.view.Enable()
	ui.progress.Hide()
}

func NewView() *view {

	vm := default_view_map()

	ui := &view{
		menu:     widget.NewSelect(maps.Keys(vm), func(s string) {}),
		view:     widget.NewMultiLineEntry(),
		status:   widget.NewLabel("status..."),
		progress: widget.NewProgressBarInfinite(),
		list:     vm,
	}

	ui.menu.OnChanged = func(s string) { ui.getView(s) }
	ui.view.TextStyle = fyne.TextStyle{Monospace: true}
	ui.view.Disable()
	ui.progress.Hidden = true
	ui.status.Hidden = false

	top := container.NewGridWithColumns(
		3,
		ui.menu, layout.NewSpacer(), layout.NewSpacer(),
	)
	bottom := container.NewMax(ui.status, ui.progress)

	ui.container = container.NewBorder(top, bottom, nil, nil, ui.view)

	return ui
}
