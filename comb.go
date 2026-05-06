package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ServIP   string
	Subnet   string
	Endpoint string
	KeepTime string
	WGPort   uint16
	HTTPPort string
	ServPriv string
	ServPub  string
}

func esacfg() *Config {
	content, err := os.Open("config/esa.conf")
	if err != nil {
		fmt.Println("INVALID FILE\n", err)
		return nil
	}
	defer func(content *os.File) {
		err := content.Close()
		if err != nil {

		}
	}(content)
	config := &Config{}
	scanner := bufio.NewScanner(content)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.TrimPrefix(parts[0], "$"))
		value := strings.TrimSpace(parts[1])
		switch key {
		case "servip":
			config.ServIP = value
		case "subnet":
			config.Subnet = value
		case "endpoint":
			config.Endpoint = value
		case "keeptime":
			config.KeepTime = value
		case "wgport":
			vul, _ := strconv.Atoi(value)
			config.WGPort = uint16(vul)
		case "httport":
			config.HTTPPort = value
		case "servpriv":
			config.ServPriv = value
		case "servpub":
			config.ServPub = value
		}
	}
	return config
}
