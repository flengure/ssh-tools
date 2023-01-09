package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/ssh"
)

var Client ssh.Client
var Session ssh.Session

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

type SSHConfigData struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Pswd string `json:"pswd,omitempty"`
}

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

func authorizedKeysCommand(publicKey string) string {
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

func getSSHKeys(dir string) (ssh.Signer, string, error) {

	privateKeyFile := filepath.Join(dir, "id_ed25519")
	publicKeyFile := filepath.Join(dir, "id_ed25519.pub")

	isPathExisting, err := pathExists(privateKeyFile)
	if err != nil {
		return nil, "", err
	}
	if !isPathExisting {
		err = generateSSHKeys(dir)
		if err != nil {
			return nil, "", err
		}
	}

	isPathExisting, err = pathExists(publicKeyFile)
	if err != nil {
		return nil, "", err
	}
	if !isPathExisting {
		ssh_keygen, err := exec.LookPath("ssh-keygen")
		if err != nil {
			log.Println("Could not find ssh-keygen")
			return nil, "", err
		}

		cmd := exec.Command(ssh_keygen, "-f", privateKeyFile, "-y", ">", publicKeyFile)
		if err := cmd.Run(); err != nil {
			log.Println("error running ssh-keygen")
			return nil, "", err
		}
	}

	f, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, "", err
	}
	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(f)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}

	f, err = os.ReadFile(publicKeyFile)
	if err != nil {
		return nil, "", err
	}
	publicKey := strings.TrimSuffix(string(string(f)), "\n")

	return signer, publicKey, nil
}

func sshSession(u, h, p string) (
	*ssh.Client, *ssh.Session, error,
) {

	var user = u
	var host = h
	var pass = p

	// home directory
	home_path, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	// local .ssh path
	ssh_path := filepath.Join(home_path, ".ssh")

	signer, publicKey, err := getSSHKeys(ssh_path)
	if err != nil {
		log.Fatal(err)
	}

	sshClientConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to the remote server and perform the SSH handshake.
	client, err := ssh.Dial("tcp", host, sshClientConfig)
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}

	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, nil, err
	}

	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr

	err = sess.Run(authorizedKeysCommand(publicKey))
	if err != nil {
		log.Fatal(err)
	}

	sess.Close()

	sess1, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	// sess, _ := Client.NewSession()
	return client, sess1, nil
}

type SSHConfigForm struct {
	nameEntry *widget.Entry
	hostEntry *widget.Entry
	portEntry *widget.Entry
	userEntry *widget.Entry
	pswdEntry *widget.Entry
}

type edit_item struct {
	name string
	path string
	cmd  string
}
type edit_items []edit_item

func (c *edit_items) names() []string {
	var is []string
	for _, i := range *c {
		is = append(is, i.name)
	}
	return is
}
func (c *edit_items) path(name string) string {
	for _, i := range *c {
		if i.name == name {
			return i.path
		}
	}
	return ""
}
func (c *edit_items) cmd(name string) string {
	for _, i := range *c {
		if i.name == name {
			return i.cmd
		}
	}
	return ""
}

type view_item struct {
	name string
	cmd  string
}
type view_items []view_item

func (c *view_items) names() []string {
	var is []string
	for _, i := range *c {
		is = append(is, i.name)
	}
	return is
}
func (c *view_items) cmd(name string) string {
	for _, i := range *c {
		if i.name == name {
			return i.cmd
		}
	}
	return ""
}
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
var edit_list = edit_items{
	{"src_accept", aclPath + "/src_accept.txt", restartFirewallCommand},
	{"src_reject", aclPath + "/src_reject.txt", restartFirewallCommand},
	{"dest_accept", aclPath + "/dest_accept.txt", restartFirewallCommand},
	{"dest_reject", aclPath + "/dest_reject.txt", restartFirewallCommand},
	{"authorized_keys", "/etc/dropbear/authorized_keys", ""},
	{"hosts", "/etc/hosts", ""},
}
var view_list = view_items{
	{"src_accept", listSetCmd("src_accept")},
	{"src_reject", listSetCmd("src_reject")},
	{"dest_accept", listDNSCmd("dest_accept")},
	{"dest_reject", listDNSCmd("dest_reject")},
	{"arp table", arpCmd},
}

const aclPath string = "/etc/firewall/user"
const restartFirewallCommand string = "fw4 restart"

type SSHConfigEditor struct {
	menu       *widget.Select
	saveButton *widget.Button
	textArea   *widget.Entry
}

type SSHConfigViewer struct {
	menu     *widget.Select
	textArea *widget.Entry
}

type SSHConfigEntry struct {
	hostEntry     *widget.Entry
	connectButton *widget.Button
	statusLabel   *widget.Label
	progressBar   *widget.ProgressBarInfinite
	editor        *SSHConfigEditor
	viewer        *SSHConfigViewer
}

type SSHConfig struct {
	data      *SSHConfigData
	form      *SSHConfigForm
	onOk      func()
	entry     *SSHConfigEntry
	onConnect func()
	client    *ssh.Client
	session   *ssh.Session
}

func (c *SSHConfig) Name() string {
	return c.data.Name
}

func (c *SSHConfig) Type() string {
	return "ssh"
}

func (c *SSHConfig) User(s string) {
	c.data.User = s
}
func (c *SSHConfig) Host(s string) {
	c.data.Host = s
}
func (c *SSHConfig) Port(s int) {
	c.data.Port = s
}
func (c *SSHConfig) Pswd(s string) {
	c.data.Pswd = s
}
func (c *SSHConfig) Load(s string) error {
	data := &SSHConfigData{}

	err := json.Unmarshal([]byte(s), data)
	if err != nil {
		return err
	}
	c.data = data
	return nil
}

func (c *SSHConfig) Data() interface{} {
	return c.data
}

func (c *SSHConfig) Form() *widget.Form {
	c.form = &SSHConfigForm{}
	nameEntry := widget.NewEntry()
	hostEntry := widget.NewEntry()
	portEntry := widget.NewEntry()
	userEntry := widget.NewEntry()
	pswdEntry := widget.NewEntry()

	portEntry.Text = "22"
	portEntry.Validator = func(s string) error {
		_, err := strconv.Atoi(s)
		return err
	}
	userEntry.Text = "root"
	pswdEntry.Password = true
	data := c.data
	if data != nil {
		nameEntry.Text = data.Name
		nameEntry.Disable()
		hostEntry.Text = data.Host
		portEntry.Text = strconv.Itoa(data.Port)
		userEntry.Text = data.User
		pswdEntry.Text = data.Pswd
	}
	c.onOk = func() {
		if c.data == nil {
			c.data = &SSHConfigData{Type: c.Type()}
		}
		c.data.Name = nameEntry.Text
		c.data.Host = hostEntry.Text
		c.data.User = userEntry.Text
		c.data.Port, _ = strconv.Atoi(portEntry.Text)
		c.data.Pswd = pswdEntry.Text
	}
	return widget.NewForm([]*widget.FormItem{
		widget.NewFormItem("Name", nameEntry),
		widget.NewFormItem("Host", hostEntry),
		widget.NewFormItem("Port", portEntry),
		widget.NewFormItem("Username", userEntry),
		widget.NewFormItem("Password", pswdEntry),
	}...)
}

func (c *SSHConfig) OnOk() {
	c.onOk()
}

func (c *SSHConfig) Connected() {
	c.entry.editor.menu.Enable()
	c.entry.editor.saveButton.Enable()
	c.entry.editor.textArea.Enable()
	c.entry.viewer.menu.Enable()
	c.entry.viewer.textArea.Enable()
}
func (c *SSHConfig) notConnected() {
	c.entry.editor.menu.Disable()
	c.entry.editor.saveButton.Disable()
	c.entry.editor.textArea.Disable()
	c.entry.viewer.menu.Disable()
	c.entry.viewer.textArea.Disable()
}
func (c *SSHConfig) ProcessStart() {
	c.entry.statusLabel.Hidden = true
	c.entry.progressBar.Hidden = false
}
func (c *SSHConfig) ProcessEnd() {
	c.entry.statusLabel.Hidden = false
	c.entry.progressBar.Hidden = true
}

func (c *SSHConfig) Connect() (*ssh.Client, *ssh.Session, error) {

	client, sess, err := sshSession(
		c.data.User,
		c.data.Host+":"+strconv.Itoa(c.data.Port),
		c.data.Pswd,
	)
	return client, sess, err
}

func (c *SSHConfig) Entry() *fyne.Container {

	c.entry = &SSHConfigEntry{
		hostEntry:     widget.NewEntry(),
		connectButton: widget.NewButton("Connect", c.onConnect),
		statusLabel:   widget.NewLabel("status..."),
		progressBar:   widget.NewProgressBarInfinite(),
		editor: &SSHConfigEditor{
			menu:       widget.NewSelect(edit_list.names(), func(s string) {}),
			saveButton: widget.NewButton("Save", func() {}),
			textArea:   widget.NewMultiLineEntry(),
		},
		viewer: &SSHConfigViewer{
			menu:     widget.NewSelect(view_list.names(), func(s string) {}),
			textArea: widget.NewMultiLineEntry(),
		},
	}
	c.entry.hostEntry.Text = c.data.User + "@" + c.data.Host
	if c.data.Port != 22 && c.data.Port != 0 {
		c.entry.hostEntry.Text += ":" + strconv.Itoa(c.data.Port)
	}
	c.entry.hostEntry.OnSubmitted = func(s string) {
		var h string
		m1 := regexp.MustCompile(`^(.*)@(.*)$`)
		m2 := regexp.MustCompile(`^(.*):(.*)$`)
		c.data.User, h = m1.ReplaceAllString(s, "$1"), m1.ReplaceAllString(s, "$2")
		c.data.Host = m2.ReplaceAllString(h, "$1")
		c.data.Port, _ = strconv.Atoi(m2.ReplaceAllString(h, "$2"))
		if c.data.User == "" {
			c.data.User = "root"
		}
		if c.data.Port < 1 || c.data.Port > 65535 {
			c.data.Port = 22
		}
	}
	c.entry.connectButton.OnTapped = func() {
		c.entry.statusLabel.SetText("connecting to " + c.entry.hostEntry.Text + "...")
		c.ProcessStart()
		client, sess, err := c.Connect()
		if err != nil {
			c.entry.statusLabel.SetText("Could not connect to " + c.entry.hostEntry.Text + err.Error())
			c.notConnected()
		} else {
			Client, Session = *client, *sess
			c.entry.statusLabel.SetText("successfully connected to " + c.entry.hostEntry.Text)
			c.Connected()
		}
		c.ProcessEnd()
	}
	c.entry.editor.menu.OnChanged = func(s string) {
		c.ProcessStart()
		f := edit_list.path(s)
		sess, _ := Client.NewSession()
		result, err := sess.Output("cat \"" + f + "\"")
		if err != nil {
			c.entry.statusLabel.SetText("failed reading " + f + ": " + err.Error())
		} else {
			c.entry.editor.textArea.SetText(string(result))
			c.entry.statusLabel.SetText("successfully read " + f)
		}
		sess.Close()
		c.ProcessEnd()
	}
	c.entry.editor.saveButton.OnTapped = func() {
		c.ProcessStart()
		sess, _ := Client.NewSession()
		w, _ := sess.StdinPipe()
		f := edit_list.path(c.entry.editor.menu.Selected)
		sess.Start("cat > \"" + f + "\"")
		w.Write([]byte(c.entry.editor.textArea.Text))
		sess.Close()
		c.entry.statusLabel.SetText("successfully saved " + f)
		c.ProcessEnd()
	}
	c.entry.viewer.menu.OnChanged = func(s string) {
		c.ProcessStart()
		cmd := view_list.cmd(s)
		sess, _ := Client.NewSession()
		result, err := sess.Output(cmd)
		if err != nil {
			c.entry.statusLabel.SetText("failed commands for " + s + ": " + err.Error())
		} else {
			c.entry.viewer.textArea.SetText(string(result))
			c.entry.statusLabel.SetText("successfully ran commands for " + s)
		}
		sess.Close()
		c.ProcessEnd()
	}
	c.entry.progressBar.Hidden = true
	c.entry.statusLabel.Hidden = false
	c.entry.editor.textArea.TextStyle = fyne.TextStyle{Monospace: true}
	c.entry.viewer.textArea.TextStyle = fyne.TextStyle{Monospace: true}
	c.notConnected()

	topSection := container.NewGridWithColumns(3, c.entry.hostEntry, layout.NewSpacer(), c.entry.connectButton)
	bottomSection := container.NewMax(c.entry.statusLabel, c.entry.progressBar)
	editorHeader := container.NewGridWithColumns(3, c.entry.editor.menu, layout.NewSpacer(), c.entry.editor.saveButton)
	viewerHeader := container.NewGridWithColumns(3, c.entry.viewer.menu, layout.NewSpacer(), layout.NewSpacer())
	editorContent := container.NewBorder(editorHeader, nil, nil, nil, c.entry.editor.textArea)
	viewerContent := container.NewBorder(viewerHeader, nil, nil, nil, c.entry.viewer.textArea)
	tabs := container.NewAppTabs(
		container.NewTabItem("Editor", editorContent),
		container.NewTabItem("Viewer", viewerContent),
	)
	content := container.NewBorder(topSection, bottomSection, nil, nil, tabs)

	return content

}