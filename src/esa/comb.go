package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ServIP   string
	Subnet   string
	Endpoint string
	KeepTime string
	WGPort   uint16
	IPPort   string
	ServPriv string
	ServPub  string
}

func esacfg() *Config {
	config, err := loadESAConfig(filepath.Join("config", "esa.conf"))
	if err != nil {
		logJSON("error", "config_load_failed", logFields{"err": err.Error()})
		return nil
	}
	return config
}

func loadESAConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	config := &Config{}
	seen := make(map[string]int)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 64*1024)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid config line %d", lineNo)
		}
		key := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(parts[0], "$")))
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			return nil, fmt.Errorf("empty config value at line %d", lineNo)
		}
		if first, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate config key %q at line %d; first seen at line %d", key, lineNo, first)
		}
		seen[key] = lineNo
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
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid wgport %q at line %d", value, lineNo)
			}
			config.WGPort = uint16(port)
		case "httport":
			config.IPPort = value
		case "servpriv":
			config.ServPriv = value
		case "servpub":
			config.ServPub = value
		default:
			logJSON("warn", "config_unknown_key", logFields{"key": key, "line": lineNo})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan config: %w", err)
	}
	if err := validateESAConfig(config); err != nil {
		return nil, err
	}
	return config, nil
}

func validateESAConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}
	for name, value := range map[string]string{"servip": config.ServIP, "subnet": config.Subnet} {
		if err := ValidateAllowedIP(value); err != nil {
			return fmt.Errorf("invalid %s: %w", name, err)
		}
	}
	if err := ValidatePubKey(config.ServPub); err != nil {
		return fmt.Errorf("invalid servpub: %w", err)
	}
	if err := validateHostPort(config.Endpoint, "endpoint"); err != nil {
		return err
	}
	if err := validateHostPort(config.IPPort, "httport"); err != nil {
		return err
	}
	if config.WGPort == 0 {
		return fmt.Errorf("wgport is required")
	}
	if strings.TrimSpace(config.KeepTime) == "" {
		return fmt.Errorf("keeptime is required")
	}
	keepalive, err := strconv.Atoi(config.KeepTime)
	if err != nil || keepalive < 0 || keepalive > 65535 {
		return fmt.Errorf("keeptime must be an integer between 0 and 65535")
	}
	if strings.TrimSpace(config.ServPriv) == "" {
		return fmt.Errorf("servpriv is required")
	}
	privateKey, err := base64.StdEncoding.DecodeString(config.ServPriv)
	if err != nil || len(privateKey) != 32 {
		return fmt.Errorf("servpriv must be a base64 encoded 32-byte key")
	}
	return nil
}

func validateHostPort(value, field string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("invalid %s %q", field, value)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid %s port %q", field, portText)
	}
	return nil
}
