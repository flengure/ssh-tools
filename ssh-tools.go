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

	myApp := app.New()
	myWindow := myApp.NewWindow("ssh tools")
	myWindow.Resize(fyne.NewSize(660, 600))

	var ssh_tools = NewSSHTools()
	ssh_tools.hostEntry.SetText("10.72.19.10:22")
	ssh_tools.password.SetText("")

	myWindow.SetContent(ssh_tools.container)

	myWindow.ShowAndRun()

}
