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
	"regexp"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/ssh"
)

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
	edit       *edit
	view       *view
	user       string
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

func (ui *ssh_tools) setHostEntry(s string) {
	var u string
	var h string
	var p int
	// s := ui.hostEntry.Text
	m1 := regexp.MustCompile(`^(.*)@(.*)$`)
	m2 := regexp.MustCompile(`^(.*):(.*)$`)
	u, h = m1.ReplaceAllString(s, "$1"), m1.ReplaceAllString(s, "$2")
	h = m2.ReplaceAllString(h, "$1")
	p, _ = strconv.Atoi(m2.ReplaceAllString(h, "$2"))
	if u == "" {
		u = "root"
	}
	if p < 1 || p > 65535 {
		p = 22
	}
	ui.user = u
	ui.host = h + ":" + strconv.Itoa(p)
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

func (ui *ssh_tools) setConnected(s string) {
	ui.connected = s
	ui.edit.connected = s
	ui.view.connected = s
}

func (ui *ssh_tools) setClient(s *ssh.Client) {
	ui.ssh = s
	ui.edit.ssh = s
	ui.view.ssh = s
}

func (ui *ssh_tools) SSHConnect() {

	ui.setStatus(fmt.Sprintf("connecting to %s as %s...", ui.host, ui.user))
	ui.showProgress()

	sshClientConfig := &ssh.ClientConfig{
		User: ui.user,
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
	client, err := ssh.Dial("tcp", ui.host, sshClientConfig)
	if err != nil {
		ui.setConnected("")
		ui.setStatus(fmt.Sprintf(
			"could not dial out to \"%s\" as \"%s\"\n%s", ui.host, ui.user, err,
		))
		ui.hideProgress()
		return
	}
	ui.setConnected(ui.host)
	ui.setClient(client)
	ui.setStatus(fmt.Sprintf(
		"successfully connected as %s to %s", ui.user, ui.host,
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
			err = sess.Run(authorizedKeysCommand(public_key))
			if err != nil {
				ui.setStatus(fmt.Sprintf(
					"could not update the remote's authorized_keys",
				))
			} else {
				ui.setStatus(fmt.Sprintf(
					"successfully updated the remote's authorized_keys",
				))
			}
		}
	}

	ui.hideProgress()
}

func NewSSHTools() ssh_tools {

	ui := ssh_tools{
		hostEntry:  widget.NewEntry(),
		password:   widget.NewEntry(),
		connect:    widget.NewButton("Connect", func() {}),
		privateKey: widget.NewEntry(),
		edit:       NewEdit(),
		view:       NewView(),
		user:       "root",
	}

	ui.hostEntry.SetText("root@10.72.19.10")
	ui.setHostEntry(ui.hostEntry.Text)
	ui.hostEntry.OnChanged = func(s string) { ui.setHostEntry(s) }
	ui.hostEntry.PlaceHolder = "user@host:port"
	ui.password.PlaceHolder = "password"
	ui.connect.Enable()
	ui.connect.OnTapped = func() { ui.SSHConnect() }

	top := container.NewGridWithColumns(
		3,
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
