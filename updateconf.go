package main

import (
	"fmt"
	"os/exec"
)

type upconf struct {
	username   string
	userpublic string
	userip     string
	keeptime   string
	wgconfpath string
	status     bool // true = add to tail  | false = find and delete Peer block
}

func updatewg(conf *upconf, iface string) error {
	if conf.userpublic == "" {
		return fmt.Errorf("empty public key")
	}
	if conf.status {
		cmd := exec.Command(
			"wg", "set", iface,
			"peer", conf.userpublic,
			"allowed-ips", conf.userip,
			"persistent-keepalive", conf.keeptime,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("add peer failed: %v\n%s", err, string(out))
		}
		fmt.Printf("PEER ADDED: %s (%s)\n", conf.username, conf.userip)
	} else {
		cmd := exec.Command(
			"wg", "set", iface,
			"peer", conf.userpublic,
			"remove",
		)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("remove peer failed: %v\n%s", err, string(out))
		}

		fmt.Printf("PEER REMOVED: %s\n", conf.username)
	}

	return nil
}
