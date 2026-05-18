package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
)

type upconf struct {
	username   string
	userpublic string
	userip     string
	keeptime   string
	wgconfpath string
	status     bool // true = add to tail  | false = find and delete Peer block
}

var wgPubKeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

func validAllowedIP(value string) bool {
	if _, _, err := net.ParseCIDR(value); err == nil {
		return true
	}
	return net.ParseIP(value) != nil
}

func validatePeer(conf *upconf) error {
	if conf.userpublic == "" {
		return fmt.Errorf("empty public key")
	}
	if !wgPubKeyRe.MatchString(conf.userpublic) {
		return fmt.Errorf("invalid public key")
	}
	if conf.userip == "" || !validAllowedIP(conf.userip) {
		return fmt.Errorf("invalid allowed IP")
	}
	return nil
}

func updatewg(ctx context.Context, conf *upconf, iface string) error {
	if err := validatePeer(conf); err != nil {
		return err
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
