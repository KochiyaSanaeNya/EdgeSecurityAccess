package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var dirPath string
	var subnet string

	fmt.Print("Enter directory path: ")
	_, err := fmt.Scanln(&dirPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR reading path: %v\n", err)
		os.Exit(1)
	}

	fmt.Print("Enter IP Subnet (e.g., 10.0.0.0/24): ")
	_, err = fmt.Scanln(&subnet)
	if err != nil || subnet == "" {
		fmt.Fprintf(os.Stderr, "ERROR reading subnet: %v\n", err)
		os.Exit(1)
	}

	inputFilePath := filepath.Join(dirPath, "users.txt")

	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID FILE PATH [%s]: %v\n", inputFilePath, err)
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

	if slashPos := strings.Index(subnet, "/"); slashPos != -1 {
		subnet = subnet[:slashPos]
	}

	prefix := subnet
	if dotPos := strings.LastIndex(subnet, "."); dotPos != -1 {
		prefix = subnet[:dotPos+1]
	}

	outputFilePath := filepath.Join(dirPath, "usrwg.conf")

	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CANNOT CREATE OUTPUT FILE [%s]: %v\n", outputFilePath, err)
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
	fmt.Printf("Success: [%s] generated.\n", outputFilePath)
}
