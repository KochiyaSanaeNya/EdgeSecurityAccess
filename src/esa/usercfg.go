package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type UserCfg struct {
	id       int
	username string
	ip       string
}

type UserStore struct {
	byName map[string]*UserCfg
}

var userStore *UserStore

func LoadUserStore(path string) (*UserStore, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open user config: %w", err)
	}
	defer file.Close()

	store := &UserStore{byName: make(map[string]*UserCfg)}
	seenIDs := make(map[int]int)
	seenIPs := make(map[string]string)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 64*1024)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid user config line %d", lineNo)
		}
		id, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || id < 0 {
			return nil, fmt.Errorf("invalid user id at line %d", lineNo)
		}
		username := strings.TrimSpace(parts[1])
		if err := ValidateUsername(username); err != nil {
			return nil, fmt.Errorf("invalid username at line %d: %w", lineNo, err)
		}
		ip, err := NormalizePeerIP(strings.TrimSpace(parts[2]))
		if err != nil {
			return nil, fmt.Errorf("invalid peer IP at line %d: %w", lineNo, err)
		}
		if first, exists := seenIDs[id]; exists {
			return nil, fmt.Errorf("duplicate user id %d at line %d; first seen at line %d", id, lineNo, first)
		}
		if first, exists := seenIPs[ip]; exists {
			return nil, fmt.Errorf("duplicate peer IP %q for %q and %q", ip, first, username)
		}
		if _, exists := store.byName[username]; exists {
			return nil, fmt.Errorf("duplicate username %q at line %d", username, lineNo)
		}
		seenIDs[id] = lineNo
		seenIPs[ip] = username
		store.byName[username] = &UserCfg{id: id, username: username, ip: ip}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan user config: %w", err)
	}
	return store, nil
}

func (s *UserStore) Get(name string) *UserCfg {
	if s == nil {
		return nil
	}
	return s.byName[name]
}
