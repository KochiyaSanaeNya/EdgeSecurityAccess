package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ERROR: Subnet parameter missing!\n")
		fmt.Fprintf(os.Stderr, "Usage: %s <10.0.0.0/24>\n", os.Args[0])
		os.Exit(1)
	}

	inputFile, err := os.Open("users.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID FILE: %v\n", err)
		os.Exit(1)
	}
	defer inputFile.Close()

	var usernames []string
	scanner := bufio.NewScanner(inputFile)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 0 || parts[0] == "" {
			continue
		}

		usernames = append(usernames, parts[0])
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading users.txt: %v\n", err)
		os.Exit(1)
	}

	subnet := os.Args[1]
	if slashPos := strings.Index(subnet, "/"); slashPos != -1 {
		subnet = subnet[:slashPos]
	}

	prefix := subnet
	if dotPos := strings.LastIndex(subnet, "."); dotPos != -1 {
		prefix = subnet[:dotPos+1]
	}

	outputFile, err := os.Create("usrwg.conf")
	if err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT CREATE OUTPUT FILE: %v\n", err)
		os.Exit(1)
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	for i, name := range usernames {
		id := i + 1
		ip := fmt.Sprintf("%s%d/32", prefix, id+1)

		output := fmt.Sprintf("%d:%s:%s\n", id, name, ip)
		_, err := writer.WriteString(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to output file: %v\n", err)
			os.Exit(1)
		}
	}

	writer.Flush()
}
