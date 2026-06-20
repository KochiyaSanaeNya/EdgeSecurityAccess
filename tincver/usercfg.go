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
	content, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := content.Close(); err != nil {
			logJSON("warn", "usercfg_close_failed", logFields{"err": err.Error()})
		}
	}()

	store := &UserStore{byName: make(map[string]*UserCfg)}
	seenIDs := make(map[int]int)
	seenIPs := make(map[string]string)
	scanner := bufio.NewScanner(content)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid user config line %d", lineNo)
		}

		idStr := strings.TrimSpace(parts[0])
		username := strings.TrimSpace(parts[1])
		ip := strings.TrimSpace(parts[2])

		id, err := strconv.Atoi(idStr)
		if err != nil || id < 0 {
			return nil, fmt.Errorf("invalid user id at line %d", lineNo)
		}
		if err := ValidateUsername(username); err != nil {
			return nil, fmt.Errorf("invalid username at line %d: %w", lineNo, err)
		}
		ip, err = NormalizePeerIP(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed ip at line %d: %w", lineNo, err)
		}
		if firstLine, exists := seenIDs[id]; exists {
			return nil, fmt.Errorf("duplicate user id %d at line %d; first seen at line %d", id, lineNo, firstLine)
		}
		if firstUser, exists := seenIPs[ip]; exists {
			return nil, fmt.Errorf("duplicate allowed ip %q for users %q and %q at line %d", ip, firstUser, username, lineNo)
		}
		if _, exists := store.byName[username]; exists {
			return nil, fmt.Errorf("duplicate username %q at line %d", username, lineNo)
		}

		seenIDs[id] = lineNo
		seenIPs[ip] = username
		store.byName[username] = &UserCfg{
			id:       id,
			username: username,
			ip:       ip,
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *UserStore) Get(name string) *UserCfg {
	if s == nil {
		return nil
	}
	return s.byName[name]
}
