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

func usrcfg(tarname string) *UserCfg {
	content, err := os.Open("config/usrwg.conf")
	if err != nil {
		fmt.Println("INVALID FILE\n", err)
		return nil
	}
	defer content.Close()
	scanner := bufio.NewScanner(content)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		if parts[1] == tarname {
			id, _ := strconv.Atoi(parts[0])
			return &UserCfg{
				id:       id,
				username: parts[1],
				ip:       parts[2],
			}
		}
	}

	return nil
}
