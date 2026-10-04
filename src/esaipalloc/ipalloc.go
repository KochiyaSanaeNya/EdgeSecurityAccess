package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	directory := readLine(reader, "Directory path: ")
	subnetText := readLine(reader, "IP subnet (for example 10.0.0.0/24): ")
	if directory == "" || subnetText == "" {
		fatal("directory and subnet are required")
	}
	prefix, err := netip.ParsePrefix(subnetText)
	if err != nil {
		fatal("invalid subnet: " + err.Error())
	}
	userPath := filepath.Join(directory, "users.txt")
	usernames, err := readUsernames(userPath)
	if err != nil {
		fatal(err.Error())
	}
	assignments, err := allocateAddresses(prefix, usernames)
	if err != nil {
		fatal(err.Error())
	}
	outputPath := filepath.Join(directory, "usrwg.conf")
	if err := writeAssignments(outputPath, assignments); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("Generated %s for %d users.\n", outputPath, len(assignments))
}

type userAssignment struct {
	ID       int
	Username string
	Address  netip.Prefix
}

func readLine(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	line, err := reader.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return ""
	}
	return strings.TrimSpace(line)
}

func readUsernames(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	seen := make(map[string]struct{})
	usernames := make([]string, 0, 16)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 64*1024)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		username := strings.TrimSpace(parts[0])
		if username == "" {
			return nil, fmt.Errorf("empty username at line %d", lineNo)
		}
		if _, exists := seen[username]; exists {
			return nil, fmt.Errorf("duplicate username %q at line %d", username, lineNo)
		}
		seen[username] = struct{}{}
		usernames = append(usernames, username)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return usernames, nil
}

func allocateAddresses(prefix netip.Prefix, usernames []string) ([]userAssignment, error) {
	prefix = prefix.Masked()
	if !prefix.IsValid() {
		return nil, fmt.Errorf("invalid subnet")
	}
	if prefix.Addr().Is4() && prefix.Bits() > 30 {
		return nil, fmt.Errorf("IPv4 subnet must have at least three usable host addresses")
	}
	if len(usernames) == 0 {
		return []userAssignment{}, nil
	}
	if prefix.Addr().Is4() {
		maxUsers := (1 << (32 - prefix.Bits())) - 3
		if len(usernames) > maxUsers {
			return nil, fmt.Errorf("subnet has room for %d users, got %d", maxUsers, len(usernames))
		}
	}
	assignments := make([]userAssignment, 0, len(usernames))
	address := prefix.Addr().Next().Next()
	for index, username := range usernames {
		if !prefix.Contains(address) {
			return nil, fmt.Errorf("address allocation exhausted")
		}
		bits := 128
		if address.Is4() {
			bits = 32
		}
		assignments = append(assignments, userAssignment{ID: index + 1, Username: username, Address: netip.PrefixFrom(address, bits)})
		address = address.Next()
	}
	return assignments, nil
}

func writeAssignments(path string, assignments []userAssignment) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".esa-ipalloc-*.tmp")
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	writer := bufio.NewWriter(file)
	for _, assignment := range assignments {
		if _, err := fmt.Fprintf(writer, "%d:%s:%s\n", assignment.ID, assignment.Username, assignment.Address); err != nil {
			_ = file.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("replace output: %w", err)
		}
		if retryErr := os.Rename(temporary, path); retryErr != nil {
			return fmt.Errorf("replace output: %w", retryErr)
		}
	}
	return nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "error:", message)
	os.Exit(1)
}
