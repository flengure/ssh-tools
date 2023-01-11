
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


type SSHConfigData1 struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Pswd string `json:"pswd,omitempty"`
	PKey string `json:"pkey,omitempty"`
}

func (s *SSHConfigData1) test (s string) {
	 s.Name := s
}

var test = func (s *SSHConfigData1) string {
	return s.name
}()

function main () {
	a = SSHConfigData1{
		name: "1"
	}
	a.
}