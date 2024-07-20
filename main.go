// mfi controls the power state of an Ubiquiti mFi Power outlet.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	appName = "mfi"

	helpArg        = "h"
	addrArg        = "a"
	hostKeyArg     = "k"
	usernameArg    = "u"
	passwordEnvArg = "e"
	outletIDArg    = "i"

	defPasswordEnv = "MFI_DEVICE_PASSWORD"

	usage = appName + `

SYNOPSIS
  ` + appName + ` -` + addrArg + ` <addr>:<port> -` + hostKeyArg + ` <ssh-host-key> [options] <on|off|status>

DESCRIPTION
  ` + appName + ` controls the power state of an Ubiquiti mFi Power outlet.

ENVIRONMENT VARIABLES
  By default, the mFi device's password is specified using the
  ` + defPasswordEnv + ` environment variable. This can be changed
  using the -` + passwordEnvArg + ` flag.

EXAMPLES

  o Turn the outlet on:

    $ read -s ` + defPasswordEnv + `
    (.. type / paste device password)
    $ export ` + defPasswordEnv + `
    $ ` + appName + ` -` + addrArg + ` 192.168.3.200:22 -` + hostKeyArg + ` 'mfi ssh-rsa AAAAB3...' on

  o Turn the outlet off:

    $ ` + appName + ` -` + addrArg + ` 192.168.3.200:22 -` + hostKeyArg + ` 'mfi ssh-rsa AAAAB3...' off

  o Check outlet status:

    $ ` + appName + ` -` + addrArg + ` 192.168.3.200:22 -` + hostKeyArg + ` 'mfi ssh-rsa AAAAB3...' status

OPTIONS
`
)

// ssh key exchanges. Copied from golang.org/x/crypto/ssh common.go.
const (
	kexAlgoDH1SHA1                = "diffie-hellman-group1-sha1"
	kexAlgoDH14SHA1               = "diffie-hellman-group14-sha1"
	kexAlgoDH14SHA256             = "diffie-hellman-group14-sha256"
	kexAlgoDH16SHA512             = "diffie-hellman-group16-sha512"
	kexAlgoECDH256                = "ecdh-sha2-nistp256"
	kexAlgoECDH384                = "ecdh-sha2-nistp384"
	kexAlgoECDH521                = "ecdh-sha2-nistp521"
	kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org"
	kexAlgoCurve25519SHA256       = "curve25519-sha256"

	// For the following kex only the client half contains a production
	// ready implementation. The server half only consists of a minimal
	// implementation to satisfy the automated tests.
	kexAlgoDHGEXSHA1   = "diffie-hellman-group-exchange-sha1"
	kexAlgoDHGEXSHA256 = "diffie-hellman-group-exchange-sha256"
)

// preferredKexAlgos key exchangs. Copied from golang.org/x/crypto/ssh common.go.
//
// preferredKexAlgos specifies the default preference for key-exchange
// algorithms in preference order. The diffie-hellman-group16-sha512 algorithm
// is disabled by default because it is a bit slower than the others.
var preferredKexAlgos = []string{
	kexAlgoCurve25519SHA256, kexAlgoCurve25519SHA256LibSSH,
	kexAlgoECDH256, kexAlgoECDH384, kexAlgoECDH521,
	kexAlgoDH14SHA256, kexAlgoDH14SHA1,
	// Added garbage:
	kexAlgoDHGEXSHA1, kexAlgoDHGEXSHA256,
	kexAlgoDH1SHA1,
}

// cipher constants. Copied from golang.org/x/crypto/ssh transport.go.
const (
	gcm128CipherID     = "aes128-gcm@openssh.com"
	gcm256CipherID     = "aes256-gcm@openssh.com"
	aes128cbcID        = "aes128-cbc"
	tripledescbcID     = "3des-cbc"
	chacha20Poly1305ID = "chacha20-poly1305@openssh.com"
)

// supportedCiphers. Copied from golang.org/x/crypto/ssh common.go.
//
// supportedCiphers lists ciphers we support but might not recommend.
var supportedCiphers = []string{
	"aes128-ctr", "aes192-ctr", "aes256-ctr",
	"aes128-gcm@openssh.com", gcm256CipherID,
	"arcfour256", "arcfour128", "arcfour",
	aes128cbcID,
	tripledescbcID,
}

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	help := flag.Bool(
		helpArg,
		false,
		"Display this information")

	addrPort := flag.String(
		addrArg,
		"",
		"The connection address in the format of `<addr>:<port>`")

	username := flag.String(
		usernameArg,
		"ubnt",
		"The device's `username`")

	passwordEnv := flag.String(
		passwordEnvArg,
		defPasswordEnv,
		"The `name` of the environment variable containing the device's password\n")

	hostKeyAKFormat := flag.String(
		hostKeyArg,
		"",
		"The device's `SSH host key` in OpenSSH authorized keys format\n"+
			"(e.g., 'ssh-rsa AAAAB3NzaC... ubiquiti mFi power')")

	outletID := flag.Int(
		outletIDArg,
		1,
		"The `ID` of the power outlet to control")

	// This prevents the flag library from running flag.PrintDefaults
	// when a flag parse error occurs
	// This makes error messages much more readable for the user :)
	flag.Usage = func() {}

	flag.Parse()

	if *help {
		os.Stderr.WriteString(usage)
		flag.PrintDefaults()
		os.Exit(1)
	}

	var err error
	flag.VisitAll(func(f *flag.Flag) {
		if err != nil {
			return
		}

		if f.Value.String() == "" {
			err = fmt.Errorf("please specify '-%s' - %s", f.Name, f.Usage)
		}
	})
	if err != nil {
		return err
	}

	switch flag.NArg() {
	case 0:
		return errors.New("please specify 'on' or 'off' as a non-flag argument")
	case 1:
		// OK.
	default:
		return errors.New("please specify only one non-flag argument")
	}

	userValue := flag.Arg(0)
	var shellCommand string

	switch userValue {
	case "on":
		shellCommand = "echo 1 > /proc/power/output" + strconv.Itoa(*outletID)
	case "off":
		shellCommand = "echo 0 > /proc/power/output" + strconv.Itoa(*outletID)
	case "status":
		shellCommand = "cat /proc/power/output" + strconv.Itoa(*outletID)
	default:
		return fmt.Errorf("unsupported power value: %q", userValue)
	}

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*hostKeyAKFormat))
	if err != nil {
		return fmt.Errorf("failed to parse device's host key - %w", err)
	}

	password := os.Getenv(*passwordEnv)
	if password == "" {
		return fmt.Errorf("please provide the mfi device's password using the %q environment variable", *passwordEnv)
	}

	sshClientConfig := &ssh.ClientConfig{
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoRSA,
			ssh.KeyAlgoRSASHA256,
			ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
		},
		User: *username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
	}

	sshClientConfig.KeyExchanges = preferredKexAlgos
	sshClientConfig.Ciphers = supportedCiphers

	sshClient, err := ssh.Dial("tcp", *addrPort, sshClientConfig)
	if err != nil {
		return fmt.Errorf("failed to setup ssh connection - %w", err)
	}
	defer sshClient.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	previousStatus := "cat /proc/power/output" + strconv.Itoa(*outletID)
	out, err := session.CombinedOutput(previousStatus)
	if err != nil {
		return fmt.Errorf("failed to get previous status for outlet id %d - %w - output: %q",
			*outletID, err, out)
	}

	out, err = session.CombinedOutput(shellCommand)
	if err != nil {
		return fmt.Errorf("failed to change power value to %q for outlet id %d - %w - output: %q",
			userValue, *outletID, err, out)
	}

	switch userValue {
	case "on":
		os.Stdout.WriteString(previousStatus + "-> on\n")
	case "off":
		os.Stdout.WriteString(previousStatus + "-> off\n")
	case "status":
		switch strings.TrimSpace(string(out)) {
		case "1":
			os.Stdout.WriteString("on\n")
		case "0":
			os.Stdout.WriteString("off\n")
		default:
			return fmt.Errorf("unknown power status value: %q", out)
		}
	}

	return nil
}

func garbageHostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	log.Printf("key: %q", ssh.MarshalAuthorizedKey(key))

	return nil
}
