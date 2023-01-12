package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/povsister/scp"
	"golang.org/x/crypto/ssh"
)

type conn struct {
	ssh     *ssh.Client
	scp     *scp.Client
	has_ssh bool
	has_scp bool
	host    string
}

func (ui *conn) get_content_scp(remotePath string) (string, error) {

	// takes a remote file path
	// returns the contents as a string
	// using scp

	sb := new(strings.Builder)

	err := ui.scp.CopyFromRemote(remotePath, sb, &scp.FileTransferOption{})
	if err != nil {
		return "", err
	}

	return sb.String(), nil
}

func (ui *conn) get_content_ssh(remotePath string) (string, error) {

	// takes a remote file path
	// returns the contents as a string
	// using ssh mode

	// open a client conn
	sess, err := ui.ssh.NewSession()
	if err != nil {
		return "", err
	}

	defer sess.Close()

	// run cat command
	// cat filename
	// where filename
	result, err := sess.Output(fmt.Sprintf("cat \"%s\"", remotePath))
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func (ui *conn) get_content(remotePath string) (string, error) {

	var result string
	var err error

	if ui.has_scp {
		result, err = ui.get_content_scp(remotePath)
		if err != nil {
			return "", err
		}
		return result, nil
	}

	result, err = ui.get_content_ssh(remotePath)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (ui *conn) set_content_scp(text, remotePath string) error {

	// takes some text and saves it to a remote file
	// replacing the existing content
	// uses scp mode

	reader := strings.NewReader(text)

	err := ui.scp.CopyToRemote(reader, remotePath, &scp.FileTransferOption{})
	if err != nil {
		return err
	}

	return nil
}

func (ui *conn) set_content_ssh(text, remotePath string) error {

	// takes some text and saves it to a remote file
	// replacing the existing content
	// uses ssh and an os specific command on the target
	// to pipe the data to a file

	// open a client conn
	sess, err := ui.ssh.NewSession()
	if err != nil {
		return err
	}

	defer sess.Close()

	// stdin pipe
	w, err := sess.StdinPipe()
	if err != nil {
		return err
	}

	defer w.Close()

	// echo to remote file
	// os specific command here
	// not very portable
	err = sess.Start(fmt.Sprintf("cat > \"%s\"", remotePath))
	if err != nil {
		return err
	}

	// write the text to the pipe
	i, err := fmt.Fprintf(w, text)
	if err != nil {
		return err
	}

	// what do I do with this ?
	fmt.Println(i)
	return nil
}

func (ui *conn) set_content(text, remotePath string) error {

	var err error

	if ui.has_scp {
		err = ui.set_content_scp(text, remotePath)
		if err != nil {
			return err
		}
		return nil
	}

	err = ui.set_content_ssh(text, remotePath)
	if err != nil {
		return err
	}

	return nil
}

func (ui *conn) run(text string) error {

	var sess *ssh.Session
	var err error

	if ui.has_scp {
		sess, err = ui.scp.NewSession()
		if err != nil {
			return err
		}
	}

	sess, err = ui.ssh.NewSession()
	if err != nil {
		return err
	}

	defer sess.Close()

	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr

	// run command specified by text
	err = sess.Run(text)
	if err != nil {
		return err
	}

	return nil
}

func (ui *conn) output(text string) (string, error) {

	var sess *ssh.Session
	var err error

	if ui.has_scp {
		sess, err = ui.scp.NewSession()
		if err != nil {
			return "", err
		}
	}

	sess, err = ui.ssh.NewSession()
	if err != nil {
		return "", err
	}

	defer sess.Close()

	// run command specified by text
	result, err := sess.Output(text)
	if err != nil {
		return "", err
	}

	return string(result), nil

}
