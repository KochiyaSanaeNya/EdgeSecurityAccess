package main

import (
	"bufio"
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
	TincPort uint16
	IPPort   string
	TincNet  string
	TincDir  string
	ServName string
	ServPub  string
}

func esacfg(path string) *Config {
	config, err := loadESAConfig(path)
	if err != nil {
		logJSON("error", "config_load_failed", logFields{"err": err.Error()})
		return nil
	}
	return config
}

func loadESAConfig(path string) (*Config, error) {
	content, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer func(content *os.File) {
		if err := content.Close(); err != nil {
			logJSON("warn", "config_close_failed", logFields{"err": err.Error()})
		}
	}(content)
	config := &Config{}
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 1024), 64*1024)
	seen := make(map[string]int)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
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
		if value == "" {
			return nil, fmt.Errorf("empty value for %q at line %d", key, lineNo)
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
		case "tincport":
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid tincport %q", value)
			}
			config.TincPort = uint16(port)
		case "httport":
			config.IPPort = value
		case "tincnet":
			config.TincNet = value
		case "tincdir":
			config.TincDir = value
		case "servname":
			config.ServName = value
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
	if err := ValidateAllowedIP(config.ServIP); err != nil {
		return fmt.Errorf("invalid servip: %w", err)
	}
	if err := ValidateAllowedIP(config.Subnet); err != nil {
		return fmt.Errorf("invalid subnet: %w", err)
	}
	if err := ValidatePubKey(config.ServPub); err != nil {
		return fmt.Errorf("invalid servpub: %w", err)
	}
	if err := ValidateTincName(config.TincNet); err != nil {
		return fmt.Errorf("invalid tincnet: %w", err)
	}
	if err := ValidateTincName(config.ServName); err != nil {
		return fmt.Errorf("invalid servname: %w", err)
	}
	if strings.TrimSpace(config.TincDir) == "" {
		return fmt.Errorf("tincdir is required")
	}
	if !isAbsConfigPath(config.TincDir) {
		return fmt.Errorf("tincdir must be absolute")
	}
	config.TincDir = filepath.Clean(config.TincDir)
	if err := validateHostPort(config.Endpoint, "endpoint"); err != nil {
		return err
	}
	if err := validateHostPort(config.IPPort, "httport"); err != nil {
		return err
	}
	if config.TincPort == 0 {
		return fmt.Errorf("tincport is required")
	}
	return nil
}

func isAbsConfigPath(path string) bool {
	path = strings.TrimSpace(path)
	if filepath.IsAbs(path) {
		return true
	}
	return strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`)
}

func validateHostPort(value string, field string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("invalid %s %q: host is empty", field, value)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid %s port %q", field, portStr)
	}
	return nil
}
