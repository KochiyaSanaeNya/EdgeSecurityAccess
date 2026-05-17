package main

import (
	"context"
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

func updatewg(ctx context.Context, conf *upconf, iface string) error {
	if conf.userpublic == "" {
		return fmt.Errorf("empty public key")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if conf.status {
		cmd := exec.CommandContext(
			ctx,
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
		cmd := exec.CommandContext(
			ctx,
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
