package main

import (
	"fmt"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/povsister/scp"
	"golang.org/x/crypto/ssh"
)

type ssh_tools struct {
	hostEntry  *widget.Entry
	password   *widget.Entry
	connectBtn *widget.Button
	privateKey *widget.Entry
	container  *fyne.Container
	conn       conn
	edit       *edit_ui
	view       *view_ui
}

func (ui *ssh_tools) set_status(s string) {
	ui.edit.set_status(s)
	ui.view.set_status(s)
}

func (ui *ssh_tools) set_error(s string) {
	ui.edit.set_error(s)
	ui.view.set_error(s)
}

func (ui *ssh_tools) progress_show(s string) {
	ui.edit.progress_show(s)
	ui.view.progress_show(s)
}

func (ui *ssh_tools) progress_hide(s string) {
	ui.edit.progress_hide(s)
	ui.view.progress_hide(s)
}

func (ui *ssh_tools) set_host(s string) {
	ui.conn.host = s
	ui.edit.conn.host = s
	ui.view.conn.host = s
}

func (ui *ssh_tools) set_has_ssh(s bool) {
	ui.conn.has_ssh = s
	ui.edit.conn.has_ssh = s
	ui.view.conn.has_ssh = s
}

func (ui *ssh_tools) set_has_scp(s bool) {
	ui.conn.has_scp = s
	ui.edit.conn.has_scp = s
	ui.view.conn.has_scp = s
}

func (ui *ssh_tools) set_ui_connected() {
	ui.connectBtn.Disable()
	ui.edit.menu.Enable()
	ui.view.menu.Enable()
}

func (ui *ssh_tools) set_connected(s string) {
	ui.set_host(s)
	ui.set_ui_connected()
	ui.connectBtn.SetText(s)
}

func (ui *ssh_tools) set_ui_not_connected() {
	ui.connectBtn.Enable()
	ui.connectBtn.SetText("connect")
	ui.edit.menu.Disable()
	ui.view.menu.Disable()
}

func (ui *ssh_tools) set_not_connected() {
	ui.set_host("")
	ui.set_ui_not_connected()
}

func (ui *ssh_tools) set_ssh(s *ssh.Client) {
	ui.conn.ssh = s
	ui.edit.conn.ssh = s
	ui.view.conn.ssh = s
	ui.set_has_ssh(true)
}

func (ui *ssh_tools) set_scp(s *scp.Client) {
	ui.conn.scp = s
	ui.edit.conn.scp = s
	ui.view.conn.scp = s
	ui.set_has_scp(true)
}

func (ui *ssh_tools) get_user_host() (string, string) {

	var user string
	var host string
	var port string
	var p int
	var q []string
	var r []string

	q = strings.Split(ui.hostEntry.Text, "@")
	if len(q) > 1 {
		user = q[0]
		host = strings.Join(q[1:], "")
	} else if len(q) > 0 {
		user = GetDefaultUsername
		host = q[0]
	} else {
		user = GetDefaultUsername
		host = "localhost"
	}

	r = strings.Split(host, ":")
	if len(r) > 1 {
		host = strings.Join(r[:len(r)-1], "")
		port = r[len(r)-1]
	} else if len(r) > 0 {
		port = "22"
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		p = 22
	}
	if p < 1 || p > 65535 {
		p = 22
	}

	return user, host + ":" + strconv.Itoa(p)

}

func new_ssh_tools() ssh_tools {

	ui := ssh_tools{
		hostEntry:  widget.NewEntry(),
		password:   widget.NewPasswordEntry(),
		connectBtn: widget.NewButton("Connect", func() {}),
		privateKey: widget.NewEntry(),
		edit:       new_edit_ui(),
		view:       new_view_ui(),
	}

	ui.hostEntry.SetText("root@10.72.19.10")
	ui.hostEntry.OnChanged = func(s string) {
		if ui.conn.host == "" {
			ui.set_ui_not_connected()
		} else {
			if ui.conn.host != s {
				ui.set_ui_not_connected()
			} else {
				ui.set_ui_connected()
			}
		}
	}

	ui.hostEntry.PlaceHolder = "user@host:port"
	ui.password.PlaceHolder = "password"
	ui.set_not_connected()

	ui.connectBtn.OnTapped = func() {

		user, host := ui.get_user_host()
		ui.progress_show(fmt.Sprintf("connecting to %s as %s...", host, user))

		sk, _ := get_keys(ui.privateKey.Text)

		sshClientConfig := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(ui.password.Text),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		sshClientConfig.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(sk.signer),
			ssh.Password(ui.password.Text),
		}

		// Connect to the remote server and perform the SSH handshake.
		//client, err := scp.NewClient(host, sshClientConfig, &scp.ClientOption{})
		sshClient, err := ssh.Dial("tcp", host, sshClientConfig)
		if err != nil {
			ui.set_not_connected()
			ui.progress_hide(fmt.Sprintf(
				"could not dial out to \"%s\" as \"%s\"\n%s", host, user, err,
			))
			return
		}
		ui.set_ssh(sshClient)

		scpClient, err := scp.NewClientFromExistingSSH(sshClient, &scp.ClientOption{})
		if err != nil {
			ui.set_not_connected()
			ui.progress_hide("fail: create scp client from existing ssh client")
			return
		}
		ui.set_scp(scpClient)

		ui.hostEntry.SetText(user + "@" + host)
		ui.set_connected(ui.hostEntry.Text)
		ui.set_status(fmt.Sprintf(
			"successfully connected as %s to %s", user, host))

		/* Write the public key associated with the private key that made
		this successful connection to the authorized_keys file of the remote
		server.
		Will do both ~/.ssh/authorized_keys and /etc/dropbear/authorized_keys
		*/

		var sb strings.Builder
		sb.WriteString("k='" + sk.public_key + "'; ")
		sb.WriteString("for d in \"/etc/dropbear\" \"~/.ssh\"; do ")
		sb.WriteString("f=\"$d/authorized_keys\"; ")
		sb.WriteString("if [ -d \"$d\" ]; then ")
		sb.WriteString("[ -f \"$f\" ] || echo \"$k\" >> \"$f\"; ")
		sb.WriteString("grep -q \"$k\" \"$f\" || echo \"$k\" >> \"$f\"; ")
		sb.WriteString("fi; done;")

		if sk.public_key == "" {
			ui.set_status("public key not found, not attempting to add to remote authorized_keys")
		} else {
			ui.set_status("public key found, attempting to update remote authorized_keys")
			err := ui.conn.run(sb.String())
			if err != nil {
				ui.set_status("could not update the remote's authorized_keys")
			} else {
				ui.set_status("successfully updated the remote's authorized_keys")
			}
		}
		ui.progress_hide(fmt.Sprintf("success: connected to %s as %s", host, user))
	}

	top := container.NewGridWithColumns(3,
		ui.hostEntry,
		ui.password,
		ui.connectBtn,
	)

	tabs := container.NewAppTabs(
		container.NewTabItem("Editor", ui.edit.container),
		container.NewTabItem("Viewer", ui.view.container),
	)

	ui.container = container.NewBorder(top, nil, nil, nil, tabs)

	return ui
}

func main() {

	myApp := app.New()
	myWindow := myApp.NewWindow("ssh tools")
	myWindow.Resize(fyne.NewSize(660, 600))

	var ssh_tools = new_ssh_tools()
	ssh_tools.hostEntry.SetText("10.72.19.10:22")
	ssh_tools.password.SetText("")

	myWindow.SetContent(ssh_tools.container)

	myWindow.ShowAndRun()

}
