package main

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/povsister/scp"
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
	scp       *scp.Client
	list      map[string]string
	text      string
	err       error
	connected string
}

func (ui *view) SetStatus(s string) {
	if s != "" {
		ui.status.SetText(s)
	}
}

func (ui *view) ProcessStart(s string) {
	ui.SetStatus(s)
	ui.progress.Show()
}

func (ui *view) ProcessEnd(s string) {
	ui.SetStatus(s)
	ui.progress.Hidden = true
}

func (ui *view) getView(s string) {

	ui.ProcessStart("Attempting to run remote commands...")

	// No host we probably have no client remember to set this
	if ui.connected == "" {
		ui.ProcessEnd("No ssh client")
		return
	}

	// open a client connection
	sess, err := ui.ssh.NewSession()
	if err != nil {
		ui.err = err
		ui.ProcessEnd("Failed to create session")
		return
	}
	defer sess.Close()
	ui.SetStatus("New Session")

	result, err := sess.Output(ui.list[s])
	if err != nil {
		ui.err = err
		ui.ProcessEnd(fmt.Sprintf(
			"failed: \"%s\"",
			ui.list[s]),
		)
		return
	}

	// command was successfully execute
	ui.text = string(result)
	ui.view.SetText(ui.text)
	ui.view.Enable()
	ui.ProcessEnd(fmt.Sprintf("success: %s", s))
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

	top := container.NewGridWithColumns(3,
		ui.menu, layout.NewSpacer(), layout.NewSpacer())
	bottom := container.NewMax(ui.status, ui.progress)

	ui.container = container.NewBorder(top, bottom, nil, nil, ui.view)

	return ui
}
