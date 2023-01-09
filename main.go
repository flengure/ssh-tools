/*
Enables ssh private key authentication for the target server
Generate a new ed25519 private key if the user does not have one
and add the corresponding public key to the target servers
authorized hosts file if it does not exist
*/
package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

func main() {

	var sshConf = SSHConfig{
		&SSHConfigData{},
		&SSHConfigForm{},
		func() {},
		&SSHConfigEntry{},
		func() {},
		nil,
		nil,
	}
	sshConf.User("root")
	sshConf.Host("10.72.19.10")
	sshConf.Port(22)
	sshConf.Pswd("M8jm7@xw4cp")

	myApp := app.New()
	myWindow := myApp.NewWindow("ssh tools")
	myWindow.Resize(fyne.NewSize(660, 600))

	content := sshConf.Entry()
	// sess, _ := Client.NewSession()
	// w, _ := sess.StdinPipe()
	// w.Write([]byte(fmt.Sprintf("%s\n", "configure")))
	// w.Write([]byte(fmt.Sprintf("%s\n", "set interfaces ethernet eth4 description")))
	// sess.Run("cat")
	// sess.Close()

	myWindow.SetContent(content)
	myWindow.ShowAndRun()

}
