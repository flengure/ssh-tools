package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/povsister/scp"
	"golang.org/x/crypto/ssh"
)

var UseSytemDefaultUsername = false
var DefaultUsername = "root"
var GetDefaultUsername = func() string {
	if UseSytemDefaultUsername {
		user, err := user.Current()
		if err != nil {
			return DefaultUsername
		}
		return user.Username
	}
	return DefaultUsername
}()

func generateSSHKeys(dir string) error {
	var err error

	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	publicKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return err
	}

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: MarshalED25519PrivateKey(privKey), // <- marshals ed25519 correctly
	}

	privateKey := pem.EncodeToMemory(pemKey)

	authorizedKey := []byte(
		fmt.Sprintf("%s %s@%s",
			strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(publicKey)), "\n"),
			currentUser.Username,
			hostname,
		),
	)

	err = os.WriteFile(filepath.Join(dir, "id_ed25519"), privateKey, 0600)
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(dir, "id_ed25519.pub"), authorizedKey, 0644)
	if err != nil {
		return err
	}

	return nil

}

type ssh_tools struct {
	hostEntry  *widget.Entry
	password   *widget.Entry
	connect    *widget.Button
	privateKey *widget.Entry
	container  *fyne.Container
	ssh        *ssh.Client
	scp        *scp.Client
	edit       *edit
	view       *view
	host       string
	connected  string
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func (s *ssh_tools) getPrivateKeyFile() string {

	if pathExists(s.privateKey.Text) {
		return s.privateKey.Text
	}

	// home directory
	home_path, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	default_ed25519_file := filepath.Join(home_path, ".ssh", "id_ed25519")

	if pathExists(default_ed25519_file) {
		fmt.Println(default_ed25519_file)
		s.privateKey.SetText(default_ed25519_file)
		return default_ed25519_file
	}

	err = generateSSHKeys(filepath.Join(home_path, ".ssh"))
	if err != nil {
		return ""
	}

	s.privateKey.SetText(default_ed25519_file)
	return default_ed25519_file

}

func (s *ssh_tools) getPublicKey() string {

	private_key_file := s.getPrivateKeyFile()
	public_key_file := private_key_file + ".pub"

	if !pathExists(public_key_file) {

		ssh_keygen, err := exec.LookPath("ssh-keygen")
		if err != nil {
			log.Println("Could not find ssh-keygen")
			return ""
		}

		cmd := exec.Command(ssh_keygen, "-f", private_key_file, "-y", ">", public_key_file)
		if err := cmd.Run(); err != nil {
			log.Println("error running ssh-keygen")
			return ""
		}
	}

	f, err := os.ReadFile(public_key_file)
	if err != nil {
		return ""
	}

	return strings.TrimSuffix(string(string(f)), "\n")

}

func (ui *ssh_tools) getSigner() (ssh.Signer, error) {

	private_key_file := ui.getPrivateKeyFile()
	if private_key_file == "" {
		return nil, nil
	}

	f, err := os.ReadFile(private_key_file)
	if err != nil {
		return nil, err
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(f)
	if err != nil {
		return nil, err
	}

	return signer, err
}

func ParseHostEntry(s string) (string, string) {
	var user string
	var host string
	var port string
	var p int
	var q []string
	var r []string
	q = strings.Split(s, "@")
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

func (ui *ssh_tools) SetHost(s string) {
	ui.hostEntry.SetText(s)
}

func (ui *ssh_tools) SetPassword(s string) {
	ui.password.SetText(s)
}

func (ui *ssh_tools) setStatus(s string) {
	ui.edit.status.SetText(s)
	ui.view.status.SetText(s)
}

func (ui *ssh_tools) hideProgress() {
	ui.edit.progress.Hide()
	ui.view.progress.Hide()
}

func (ui *ssh_tools) showProgress() {
	ui.edit.progress.Show()
	ui.view.progress.Show()
}

func (ui *ssh_tools) setUIConnected() {
	ui.connect.Disable()
	ui.edit.menu.Enable()
	ui.view.menu.Enable()
}
func (ui *ssh_tools) setConnected(s string) {
	ui.connected = s
	ui.edit.connected = s
	ui.view.connected = s
	ui.setUIConnected()
}

func (ui *ssh_tools) setUINotConnected() {
	ui.connect.Enable()
	ui.edit.menu.Disable()
	ui.view.menu.Disable()
}
func (ui *ssh_tools) setNotConnected() {
	ui.connected = ""
	ui.edit.connected = ""
	ui.view.connected = ""
	ui.setUINotConnected()
}

func (ui *ssh_tools) setSSHClient(s *ssh.Client) {
	ui.ssh = s
	ui.edit.ssh = s
	ui.view.ssh = s
}

func (ui *ssh_tools) setSCPClient(s *scp.Client) {
	ui.scp = s
	ui.edit.scp = s
	ui.view.scp = s
}

func (ui *ssh_tools) authorizedKeys() string {
	publicKey := ui.getPublicKey()
	if publicKey == "" {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("k='" + publicKey + "'; ")
	sb.WriteString("for d in \"/etc/dropbear\" \"~/.ssh\"; do ")
	sb.WriteString("f=\"$d/authorized_keys\"; ")
	sb.WriteString("if [ -d \"$d\" ]; then ")
	sb.WriteString("[ -f \"$f\" ] || echo \"$k\" >> \"$f\"; ")
	sb.WriteString("grep -q \"$k\" \"$f\" || echo \"$k\" >> \"$f\"; ")
	sb.WriteString("fi; done;")
	return sb.String()
}

func (ui *ssh_tools) SSHConnect() {

	user, host := ParseHostEntry(ui.hostEntry.Text)

	fmt.Println(ParseHostEntry(ui.hostEntry.Text))

	fmt.Println(user, host)
	ui.edit.ProcessStart(fmt.Sprintf("connecting to %s as %s...", host, user))

	sshClientConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(ui.password.Text),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	signer, err := ui.getSigner()
	if err != nil {
		ui.setStatus(fmt.Sprintf(
			"could not get signer proceed with password only",
		))
	} else {
		sshClientConfig.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			ssh.Password(ui.password.Text),
		}
	}

	// Connect to the remote server and perform the SSH handshake.
	//client, err := scp.NewClient(host, sshClientConfig, &scp.ClientOption{})
	sshClient, err := ssh.Dial("tcp", host, sshClientConfig)
	if err != nil {
		ui.setNotConnected()
		ui.edit.ProcessEnd(fmt.Sprintf(
			"could not dial out to \"%s\" as \"%s\"\n%s", host, user, err,
		))
		return
	}
	ui.setSSHClient(sshClient)

	scpClient, err := scp.NewClientFromExistingSSH(sshClient, &scp.ClientOption{})
	if err != nil {
		ui.setNotConnected()
		ui.edit.ProcessEnd(fmt.Sprintf(
			"could not create scp client from existing ssh client",
		))
		return
	}
	ui.setSCPClient(scpClient)
	ui.setConnected(ui.hostEntry.Text)
	ui.setStatus(fmt.Sprintf(
		"successfully connected as %s to %s", user, host,
	))

	/* Write the public key associated with the private key that made
	this successful connection to the authorized_keys file of the remote
	server.
	Will do both ~/.ssh/authorized_keys and /etc/dropbear/authorized_keys
	*/
	public_key := ui.getPublicKey()

	if public_key == "" {
		ui.setStatus(fmt.Sprintf(
			"public key not found, not attempting to add to remote authorized_keys",
		))
	} else {

		ui.setStatus(fmt.Sprintf(
			"public key found, attempting to update remote authorized_keys",
		))
		sess, err := ui.ssh.NewSession()
		if err != nil {
			ui.setStatus(fmt.Sprintf(
				"could not create session",
			))
		} else {
			defer sess.Close()
			sess.Stdout = os.Stdout
			sess.Stderr = os.Stderr
			err = sess.Run(ui.authorizedKeys())
			if err != nil {
				ui.setStatus("could not update the remote's authorized_keys")
			} else {
				ui.setStatus("successfully updated the remote's authorized_keys")
			}
		}
	}

	ui.hideProgress()
}

func NewSSHTools() ssh_tools {

	ui := ssh_tools{
		hostEntry:  widget.NewEntry(),
		password:   widget.NewPasswordEntry(),
		connect:    widget.NewButton("Connect", func() {}),
		privateKey: widget.NewEntry(),
		edit:       NewEdit(),
		view:       NewView(),
	}

	ui.hostEntry.SetText("root@10.72.19.10")
	ui.hostEntry.OnChanged = func(s string) {
		if ui.connected == "" {
			ui.setUINotConnected()
		} else {
			if ui.connected != s {
				ui.setUINotConnected()
			} else {
				ui.setUIConnected()
			}
		}
	}
	ui.hostEntry.PlaceHolder = "user@host:port"
	ui.password.PlaceHolder = "password"
	ui.setNotConnected()
	ui.connect.OnTapped = func() { ui.SSHConnect() }

	fmt.Println(ParseHostEntry(ui.hostEntry.Text))

	top := container.NewGridWithColumns(3,
		ui.hostEntry,
		ui.password,
		ui.connect,
	)

	tabs := container.NewAppTabs(
		container.NewTabItem("Editor", ui.edit.container),
		container.NewTabItem("Viewer", ui.view.container),
	)

	ui.container = container.NewBorder(top, nil, nil, nil, tabs)

	return ui
}
