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
	"strings"

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

func path_exists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func generate_ssh_keys() (string, error) {

	// home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	private := filepath.Join(home, ".ssh", "id_ed25519")
	if path_exists(private) {
		return private, nil
	}
	fmt.Println(private)

	public := private + ".pub"
	user, _ := user.Current()
	host, _ := os.Hostname()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	publicKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: MarshalED25519PrivateKey(privKey), // <- marshals ed25519 correctly
	}

	privateKey := pem.EncodeToMemory(pemKey)

	authorizedKey := []byte(
		fmt.Sprintf("%s %s@%s",
			strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(publicKey)), "\n"),
			user.Username,
			host,
		),
	)

	err = os.WriteFile(private, privateKey, 0600)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(public, authorizedKey, 0644)
	if err != nil {
		return "", err
	}

	return private, nil

}

type ssh_key struct {
	private_key_file string
	public_key_file  string
	public_key       string
	signer           ssh.Signer
}

func get_keys(s string) (ssh_key, error) {

	o := ssh_key{}

	if s == "" || !path_exists(s) {
		new_private, err := generate_ssh_keys()
		if err != nil {
			return o, err
		}
		o.private_key_file = new_private
	} else {
		o.private_key_file = s
	}
	o.public_key_file = o.private_key_file + ".pub"

	if !path_exists(o.public_key_file) {

		ssh_keygen, err := exec.LookPath("ssh-keygen")
		if err != nil {
			log.Println("Could not find ssh-keygen")
		}

		cmd := exec.Command(
			ssh_keygen, "-f", o.private_key_file, "-y", ">", o.public_key_file)

		if err := cmd.Run(); err != nil {
			log.Println("error running ssh-keygen")
		}
	}

	if path_exists(o.public_key_file) {

		f, err := os.ReadFile(o.public_key_file)
		if err != nil {
			log.Println("error reading public key file" + o.public_key_file)
		} else {
			o.public_key = strings.TrimSuffix(string(string(f)), "\n")
		}
	}

	if path_exists(o.private_key_file) {

		f, err := os.ReadFile(o.private_key_file)
		if err != nil {
			log.Println("error reading private key file" + o.private_key_file)
		} else {
			// Create the Signer for this private key.
			signer, err := ssh.ParsePrivateKey(f)
			if err != nil {
				log.Println("error parsing private key file" + o.private_key_file)
			} else {
				o.signer = signer
			}
		}
	}

	return o, nil
}
