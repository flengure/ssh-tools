/*
Enables ssh private key authentication for the target server
Generate a new ed25519 private key if the user does not have one
and add the corresponding public key to the target servers
authorized hosts file if it does not exist
*/

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
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/fyne-io/terminal"
	"golang.org/x/crypto/ssh"
)

var Client ssh.Client
var Session ssh.Session

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

type SSHConfigData struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Pswd string `json:"pswd,omitempty"`
	PKey string `json:"pkey,omitempty"`
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

	if !pathExists(privateKeyFile) {
		err := generateSSHKeys(dir)
		if err != nil {
			return nil, "", err
		}
	}

	if !pathExists(publicKeyFile) {
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

func sshClient(u, h, p string) (*ssh.Client, error) {

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
		return nil, err
	}
	defer sess.Close()

	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr

	err = sess.Run(authorizedKeysCommand(publicKey))
	if err != nil {
		log.Fatal(err)
	}
	return client, nil
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
	textLoaded string
}

type SSHConfigViewer struct {
	menu     *widget.Select
	textArea *widget.Entry
}

type SSHConfigRemote struct {
	terminal *terminal.Terminal
}
type SSHConfigLocal struct {
	terminal *terminal.Terminal
}
type SSHConfigEntry struct {
	hostEntry     *widget.Entry
	connectedHost string
	pswdEntry     *widget.Entry
	connectButton *widget.Button
	statusLabel   *widget.Label
	progressBar   *widget.ProgressBarInfinite
	editor        *SSHConfigEditor
	viewer        *SSHConfigViewer
	remote        *SSHConfigRemote
	local         *SSHConfigLocal
}

type SSHConfig struct {
	data       *SSHConfigData
	form       *SSHConfigForm
	onOk       func()
	entry      *SSHConfigEntry
	onConnect  func()
	connection string
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
	c.connection = c.entry.hostEntry.Text
	c.entry.connectButton.Disable()
	c.entry.connectButton.SetText("Connected to " + c.entry.hostEntry.Text)
	c.entry.editor.menu.Enable()
	c.entry.viewer.menu.Enable()
	// sess, err := Client.NewSession()
	// if err == nil {
	// 	in, _ := sess.StdinPipe()
	// 	out, _ := sess.StdoutPipe()
	// 	go sess.Run("$SHELL || bash")
	// 	go func() {
	// 		_ = c.entry.remote.terminal.RunWithConnection(in, out)
	// 		// a.Quit()
	// 	}()
	// } else {
	// 	c.entry.statusLabel.SetText("Unable to create session")
	// }

}
func (c *SSHConfig) notConnected() {
	c.connection = ""
	c.entry.connectButton.Enable()
	c.entry.connectButton.SetText("Connect")
	c.entry.editor.menu.SetSelected("")
	c.entry.editor.menu.Disable()
	c.entry.editor.saveButton.Disable()
	c.entry.editor.textArea.SetText("")
	c.entry.editor.textArea.Disable()
	c.entry.viewer.menu.SetSelected("")
	c.entry.viewer.menu.Disable()
	c.entry.viewer.textArea.SetText("")
	c.entry.viewer.textArea.Disable()
}
func (c *SSHConfig) ProcessStart(s string) {
	c.entry.statusLabel.SetText(s)
	c.entry.statusLabel.Hidden = true
	c.entry.progressBar.Hidden = false
}
func (c *SSHConfig) ProcessEnd(s string) {
	c.entry.statusLabel.SetText(s)
	c.entry.statusLabel.Hidden = false
	c.entry.progressBar.Hidden = true
}

func (c *SSHConfig) Connect() (*ssh.Client, error) {

	client, err := sshClient(
		c.data.User,
		c.data.Host+":"+strconv.Itoa(c.data.Port),
		c.data.Pswd,
	)
	return client, err
}

func (c *SSHConfig) Entry() *fyne.Container {

	c.entry = &SSHConfigEntry{
		hostEntry:     widget.NewEntry(),
		connectedHost: "",
		pswdEntry:     widget.NewPasswordEntry(),
		connectButton: widget.NewButton("Connect", c.onConnect),
		statusLabel:   widget.NewLabel("status..."),
		progressBar:   widget.NewProgressBarInfinite(),
		editor: &SSHConfigEditor{
			menu:       widget.NewSelect(edit_list.names(), func(s string) {}),
			saveButton: widget.NewButton("Save", func() {}),
			textArea:   widget.NewMultiLineEntry(),
			textLoaded: "",
		},
		viewer: &SSHConfigViewer{
			menu:     widget.NewSelect(view_list.names(), func(s string) {}),
			textArea: widget.NewMultiLineEntry(),
		},
		remote: &SSHConfigRemote{
			terminal: terminal.New(),
		},
		local: &SSHConfigLocal{
			terminal: terminal.New(),
		},
	}
	c.entry.hostEntry.PlaceHolder = "user@host:port"
	c.entry.hostEntry.Text = c.data.User + "@" + c.data.Host
	if c.data.Port != 22 && c.data.Port != 0 {
		c.entry.hostEntry.Text += ":" + strconv.Itoa(c.data.Port)
	}
	c.entry.hostEntry.OnChanged = func(s string) {
		var u string
		var h string
		var p int
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
		c.data.User = u
		c.data.Host = h
		c.data.Port = p
		if s != c.entry.connectedHost || s == "" {
			c.notConnected()

		} else {
			c.Connected()
		}

	}

	c.entry.pswdEntry.PlaceHolder = "Password"
	c.entry.pswdEntry.OnChanged = func(s string) { c.data.Pswd = s }

	c.entry.connectButton.OnTapped = func() {
		c.ProcessStart(fmt.Sprintf("connecting to \"%s\"...", c.entry.hostEntry.Text))

		sshClientConfig := &ssh.ClientConfig{
			User: c.data.User,
			Auth: []ssh.AuthMethod{
				ssh.Password(c.data.Pswd),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		if c.data.PKey == "" || !pathExists(c.data.PKey) {
			// home directory
			home_path, err := os.UserHomeDir()
			if err == nil {
				// local .ssh path
				ssh_path := filepath.Join(home_path, ".ssh")
				signer, _, err := getSSHKeys(ssh_path)
				if err == nil {
					sshClientConfig.Auth = []ssh.AuthMethod{
						ssh.PublicKeys(signer),
						ssh.Password(c.data.Pswd),
					}
					c.data.PKey = filepath.Join(ssh_path, "id_25519")
				}
			}
		}

		// Connect to the remote server and perform the SSH handshake.

		client, err := ssh.Dial("tcp", fmt.Sprintf(
			"%s:%s", c.data.Host, strconv.Itoa(c.data.Port),
		), sshClientConfig)
		if err != nil {
			c.connection = ""
			c.ProcessEnd(fmt.Sprintf(
				"could not dial to \"%s\"", c.entry.hostEntry.Text,
			))
			return
		}
		c.connection = c.entry.hostEntry.Text
		Client = *client

		c.entry.connectedHost = c.entry.hostEntry.Text
		c.Connected()
		c.ProcessEnd(fmt.Sprintf(
			"successfully connected to \"%s\"", c.entry.hostEntry.Text,
		))

		/* Write the public key associated with the private key that made
		this successful connection to the authorized_keys file of the remote
		server.
		Will do both ~/.ssh/authorized_keys and /etc/dropbear/authorized_keys
		*/
		sess, err := client.NewSession()
		if err == nil {
			defer sess.Close()
			// home directory
			home_path, err := os.UserHomeDir()
			if err == nil {
				// local .ssh path
				ssh_path := filepath.Join(home_path, ".ssh")
				_, publicKey, err := getSSHKeys(ssh_path)
				if err == nil {
					sess.Stdout = os.Stdout
					sess.Stderr = os.Stderr
					err = sess.Run(authorizedKeysCommand(publicKey))
					if err != nil {
						c.ProcessEnd("could not not update authorized keys")
					}
				}
			}
		}
	}

	c.entry.editor.menu.OnChanged = func(s string) {
		fil := edit_list.path(s)
		c.ProcessStart(fmt.Sprintf("reading \"%s\"...", fil))
		sess, err := Client.NewSession()
		if err != nil {
			c.ProcessEnd(fmt.Sprintf("unable to start session: %s", err.Error()))
			return
		}
		defer sess.Close()
		result, err := sess.Output(fmt.Sprintf("cat \"%s\"", fil))
		if err != nil {
			c.ProcessEnd(fmt.Sprintf("failed reading \"%s\": %s", fil, err.Error()))
			return
		}
		c.entry.editor.textLoaded = string(result)
		c.entry.editor.textArea.SetText(c.entry.editor.textLoaded)
		// fmt.Println(c.entry.editor.text)
		c.entry.editor.textArea.Enable()
		// c.entry.editor.saveButton.Enable()
		c.ProcessEnd(fmt.Sprintf("successfully read \"%s\"", fil))
	}
	c.entry.editor.saveButton.Disable()
	c.entry.editor.saveButton.OnTapped = func() {
		c.ProcessStart("Saving...")
		fil := edit_list.path(c.entry.editor.menu.Selected)
		cmd := edit_list.cmd(c.entry.editor.menu.Selected)
		sess1, err := Client.NewSession()
		if err != nil {
			c.ProcessEnd(fmt.Sprintf("unable to start session: %s", err.Error()))
			return
		}
		defer sess1.Close()
		w, err := sess1.StdinPipe()
		if err != nil {
			c.ProcessEnd(fmt.Sprintf("unable to open StdinPipe: %s", err.Error()))
			return
		}
		defer w.Close()
		err = sess1.Start(fmt.Sprintf("cat > \"%s\"", fil))
		if err != nil {
			c.ProcessEnd(fmt.Sprintf("unable to start session: %s", err.Error()))
			return
		}
		// i, err := w.Write([]byte(c.entry.editor.textArea.Text))
		i, err := fmt.Fprintf(w, c.entry.editor.textArea.Text)
		if err != nil {
			c.ProcessEnd(fmt.Sprintf("could not write to StdinPipe: %s", err.Error()))
			return
		}
		fmt.Println(i)

		c.entry.editor.textLoaded = c.entry.editor.textArea.Text
		c.entry.statusLabel.SetText(fmt.Sprintf("successfully saved \"%s\"", fil))

		sess2, err := Client.NewSession()
		if err != nil {
			c.ProcessEnd(fmt.Sprintf("could not create session: %s", err.Error()))
			return
		}
		defer sess2.Close()
		sess2.Stdout = os.Stdout
		sess2.Stderr = os.Stderr
		err = sess2.Run(cmd)
		if err != nil {
			c.ProcessEnd(fmt.Sprintf("failed running \"%s\": %s", cmd, err.Error()))
			return
		}
		c.ProcessEnd(fmt.Sprintf("successfully saved \"%s\" and ran \"%s\"", fil, cmd))
	}
	c.entry.editor.textArea.OnChanged = func(s string) {
		if s == c.entry.editor.textLoaded {
			c.entry.editor.saveButton.Disable()
		} else {
			c.entry.editor.saveButton.Enable()
		}
	}

	c.entry.viewer.menu.OnChanged = func(s string) {
		c.ProcessStart(fmt.Sprintf("running \"%s\"...", s))
		cmd := view_list.cmd(s)
		sess, _ := Client.NewSession()
		result, err := sess.Output(cmd)
		if err != nil {
			c.ProcessEnd(fmt.Sprintf("failed commands for \"%s\": %s", s, err.Error()))
			return
		}
		c.entry.viewer.textArea.SetText(string(result))
		c.entry.viewer.textArea.Enable()
		sess.Close()
		c.ProcessEnd(fmt.Sprintf("successfully ran commands for \"%s\"", s))
	}

	c.entry.progressBar.Hidden = true
	c.entry.statusLabel.Hidden = false
	c.entry.editor.textArea.TextStyle = fyne.TextStyle{Monospace: true}
	c.entry.viewer.textArea.TextStyle = fyne.TextStyle{Monospace: true}

	topSection := container.NewGridWithColumns(3, c.entry.hostEntry, c.entry.pswdEntry, c.entry.connectButton)
	bottomSection := container.NewMax(c.entry.statusLabel, c.entry.progressBar)
	editorHeader := container.NewGridWithColumns(3, c.entry.editor.menu, layout.NewSpacer(), c.entry.editor.saveButton)
	viewerHeader := container.NewGridWithColumns(3, c.entry.viewer.menu, layout.NewSpacer(), layout.NewSpacer())
	editorContent := container.NewBorder(editorHeader, nil, nil, nil, c.entry.editor.textArea)
	viewerContent := container.NewBorder(viewerHeader, nil, nil, nil, c.entry.viewer.textArea)
	tabs := container.NewAppTabs(
		container.NewTabItem("Editor", editorContent),
		container.NewTabItem("Viewer", viewerContent),
		// container.NewTabItem("Remote", c.entry.remote.terminal),
		// container.NewTabItem("local", c.entry.local.terminal),
	)
	content := container.NewBorder(topSection, bottomSection, nil, nil, tabs)

	// go func() {
	// 	_ = c.entry.local.terminal.RunLocalShell()
	// }()

	return content

}

func main() {

	var sshConf = SSHConfig{
		&SSHConfigData{},
		&SSHConfigForm{},
		func() {},
		&SSHConfigEntry{},
		func() {},
		"",
	}
	sshConf.User("root")
	sshConf.Host("10.72.19.10")
	sshConf.Port(22)
	sshConf.Pswd("")

	myApp := app.New()
	myWindow := myApp.NewWindow("ssh tools")
	myWindow.Resize(fyne.NewSize(660, 600))

	content := sshConf.Entry()

	myWindow.SetContent(content)
	myWindow.ShowAndRun()

}
