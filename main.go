package main

import (
	"crypto/subtle"
	"fmt"
	"github.com/flynn/json5"
	"github.com/haruue-net/honks/socks5"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"io"
	"log"
	"net"
	"os"
	"time"
)

func showUsage(writer io.Writer) {
	fmt.Fprintf(writer, "Usage: %s config.json\n", os.Args[0])
}

var config Config
var users map[string]User // username => user

func main() {
	if len(os.Args) != 2 {
		showUsage(os.Stderr)
		os.Exit(22)
	}

	switch os.Args[1] {
	case "-h":
		fallthrough
	case "--help":
		showUsage(os.Stdout)
		os.Exit(0)
	default:
		configFilePath := os.Args[1]
		err := readConfig(configFilePath)
		if err != nil {
			logFatal("cannot parse config from %s: %s\n", configFilePath, err)
			os.Exit(1)
		}
	}

	af := authFunc
	if len(config.Users) == 0 {
		af = nil
	}

	server, err := socks5.NewServer(transport.DefaultClientTransport, config.Listen,
		af, time.Duration(config.Timeout)*time.Second,
		nil, config.DisableUDP,
		logTCPReqFunc, logTCPErrorFunc, logUDPAssocFunc, logUDPErrorFunc)
	if err != nil {
		log.Printf("[fatal] cannot create server: %s\n", err)
		os.Exit(1)
	}

	logInfo("listen on %s\n", config.Listen)
	logFatal("server exit: %s\n", server.ListenAndServe())
}

func readConfig(path string) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	err = json5.NewDecoder(file).Decode(&config)
	if err != nil {
		return
	}

	users = make(map[string]User)
	for _, user := range config.Users {
		users[user.Username] = user
	}

	return
}

func authFunc(username, password string) bool {
	if user, ok := users[username]; ok {
		if subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) == 1 {
			logVerbose("user %s authenticated\n", username)
			return true
		}
		logError("user %s authentication failed\n", username)
		return false
	}
	logError("user %s not found\n", username)
	return false
}

func logTCPReqFunc(addr net.Addr, reqAddr string, action acl.Action, arg string) {
	logVerbose("tcp request: %s => %s\n", addr, reqAddr)
}

func logTCPErrorFunc(addr net.Addr, reqAddr string, err error) {
	logVerbose("tcp error: %s => %s: %s\n", addr, reqAddr, err)
}

func logUDPAssocFunc(addr net.Addr) {
	logVerbose("udp association from %s\n", addr)
}

func logUDPErrorFunc(addr net.Addr, err error) {
	logVerbose("udp association error from %s: %s\n", addr, err)
}
