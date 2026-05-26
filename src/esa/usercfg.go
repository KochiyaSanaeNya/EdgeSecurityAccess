package main

import (
	"bufio"
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
		_ = content.Close()
	}()

	store := &UserStore{byName: make(map[string]*UserCfg)}
	scanner := bufio.NewScanner(content)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}

		idStr := strings.TrimSpace(parts[0])
		username := strings.TrimSpace(parts[1])
		ip := strings.TrimSpace(parts[2])

		id, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}

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

/*func usrcfg(tarname string) *UserCfg {
	if userStore != nil {
		return userStore.Get(tarname)
	}
	content, err := os.Open("config/usrwg.conf")
	if err != nil {
		fmt.Println("INVALID FILE\n", err)
		return nil
	}
	defer content.Close()

	scanner := bufio.NewScanner(content)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 3)

		if len(parts) != 3 {
			continue
		}

		idStr := strings.TrimSpace(parts[0])
		username := strings.TrimSpace(parts[1])
		ip := strings.TrimSpace(parts[2])

		if username != tarname {
			continue
		}

		id, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}

		return &UserCfg{
			id:       id,
			username: username,
			ip:       ip,
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("SCAN ERROR\n", err)
	}

	return nil
}
*/
