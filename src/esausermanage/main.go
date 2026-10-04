package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

const (
	minPasswordLength = 6
	maxPasswordLength = 256
	argonMemory       = 64 * 1024
	argonIterations   = 3
	argonParallelism  = 4
	argonSaltLength   = 16
	argonHashLength   = 32
)

type Account struct {
	Username string
	Password string
}

func hashPassword(password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	digest := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonHashLength)
	return "$argon2id$v=19$m=" + strconv.Itoa(argonMemory) + ",t=" + strconv.Itoa(argonIterations) + ",p=" + strconv.Itoa(argonParallelism) + "$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(digest), nil
}

func verifyPassword(password, encodedHash string) (bool, error) {
	params, salt, expected, err := parsePasswordHash(encodedHash)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

type passwordHashParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func parsePasswordHash(encodedHash string) (passwordHashParams, []byte, []byte, error) {
	parts := strings.Split(strings.TrimSpace(encodedHash), "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return passwordHashParams{}, nil, nil, errors.New("invalid argon2id hash format")
	}
	params := map[string]uint64{}
	for _, item := range strings.Split(parts[3], ",") {
		key, value, ok := strings.Cut(item, "=")
		if !ok || (key != "m" && key != "t" && key != "p") {
			return passwordHashParams{}, nil, nil, errors.New("invalid argon2id parameters")
		}
		if _, exists := params[key]; exists {
			return passwordHashParams{}, nil, nil, errors.New("duplicate argon2id parameter")
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return passwordHashParams{}, nil, nil, errors.New("invalid argon2id parameters")
		}
		params[key] = parsed
	}
	if len(params) != 3 || params["m"] < 32*1024 || params["m"] > 256*1024 || params["t"] < 1 || params["t"] > 10 || params["p"] < 1 || params["p"] > 8 {
		return passwordHashParams{}, nil, nil, errors.New("argon2id parameters out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return passwordHashParams{}, nil, nil, errors.New("invalid argon2id salt")
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return passwordHashParams{}, nil, nil, errors.New("invalid argon2id digest")
	}
	return passwordHashParams{memory: uint32(params["m"]), iterations: uint32(params["t"]), parallelism: uint8(params["p"])}, salt, expected, nil
}

func loadAccounts(path string) ([]Account, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	accounts := make([]Account, 0, 16)
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 64*1024)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid account line %d", lineNo)
		}
		username, encodedHash := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if err := validateUsername(username); err != nil {
			return nil, fmt.Errorf("invalid username at line %d: %w", lineNo, err)
		}
		if _, exists := seen[username]; exists {
			return nil, fmt.Errorf("duplicate username %q at line %d", username, lineNo)
		}
		if err := ValidatePasswordHash(encodedHash); err != nil {
			return nil, fmt.Errorf("invalid password hash at line %d: %w", lineNo, err)
		}
		seen[username] = struct{}{}
		accounts = append(accounts, Account{Username: username, Password: encodedHash})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read accounts: %w", err)
	}
	return accounts, nil
}

func saveAccounts(path string, accounts []Account) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("account path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create account directory: %w", err)
	}
	tmp, err := os.CreateTemp(directory, ".esa-users-*.tmp")
	if err != nil {
		return fmt.Errorf("create account file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	writer := bufio.NewWriter(tmp)
	seen := make(map[string]struct{}, len(accounts))
	for _, account := range accounts {
		if err := validateUsername(account.Username); err != nil {
			_ = tmp.Close()
			return err
		}
		if _, exists := seen[account.Username]; exists {
			_ = tmp.Close()
			return fmt.Errorf("duplicate username %q", account.Username)
		}
		if err := ValidatePasswordHash(account.Password); err != nil {
			_ = tmp.Close()
			return err
		}
		seen[account.Username] = struct{}{}
		if _, err := fmt.Fprintf(writer, "%s:%s\n", account.Username, account.Password); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("replace account file: %w", err)
		}
		if retryErr := os.Rename(tmpPath, path); retryErr != nil {
			return fmt.Errorf("replace account file: %w", retryErr)
		}
	}
	return nil
}

func ValidatePasswordHash(value string) error {
	_, _, _, err := parsePasswordHash(value)
	return err
}

func validateUsername(value string) error {
	if value == "" || len(value) > 32 {
		return errors.New("username must contain 1 to 32 characters")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("_.-", r) {
			continue
		}
		return errors.New("username contains invalid characters")
	}
	return nil
}

func validatePassword(value string) error {
	if len(value) < minPasswordLength || len(value) > maxPasswordLength {
		return fmt.Errorf("password must contain %d to %d bytes", minPasswordLength, maxPasswordLength)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return errors.New("password contains control characters")
		}
	}
	return nil
}

func printAccounts(accounts []Account) {
	fmt.Println("\n==================== User List ====================")
	for index, account := range accounts {
		fmt.Printf("%d. %s\n", index+1, account.Username)
	}
	fmt.Println("===================================================")
}

func readInput(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	return strings.TrimSpace(value)
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	path := readInput(reader, "Enter the account file path: ")
	if path == "" {
		fmt.Fprintln(os.Stderr, "account file path is required")
		return
	}
	accounts, err := loadAccounts(path)
	if err != nil {
		if os.IsNotExist(err) {
			accounts = []Account{}
		} else {
			fmt.Fprintln(os.Stderr, "load accounts:", err)
			return
		}
	}

	save := func() {
		if err := saveAccounts(path, accounts); err != nil {
			fmt.Println("Save failed:", err)
		} else {
			fmt.Println("Saved")
		}
	}
	for {
		printAccounts(accounts)
		fmt.Println("1. Create user")
		fmt.Println("2. Verify user")
		fmt.Println("3. Update password")
		fmt.Println("4. Delete user")
		fmt.Println("5. Exit")
		switch readInput(reader, "Choice: ") {
		case "1":
			username := readInput(reader, "Username: ")
			if err := validateUsername(username); err != nil {
				fmt.Println("Error:", err)
				continue
			}
			found := false
			for _, account := range accounts {
				found = found || account.Username == username
			}
			if found {
				fmt.Println("Error: username already exists")
				continue
			}
			password := readInput(reader, "Password: ")
			hash, err := hashPassword(password)
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}
			accounts = append(accounts, Account{Username: username, Password: hash})
			save()
		case "2":
			username := readInput(reader, "Username: ")
			found := false
			for _, account := range accounts {
				if account.Username == username {
					found = true
					password := readInput(reader, "Password: ")
					match, err := verifyPassword(password, account.Password)
					if err != nil || !match {
						fmt.Println("Password verification failed")
					} else {
						fmt.Println("Password verified")
					}
					break
				}
			}
			if !found {
				fmt.Println("User not found")
			}
		case "3":
			username := readInput(reader, "Username: ")
			found := false
			for index := range accounts {
				if accounts[index].Username == username {
					found = true
					password := readInput(reader, "New password: ")
					hash, err := hashPassword(password)
					if err != nil {
						fmt.Println("Error:", err)
					} else {
						accounts[index].Password = hash
						save()
					}
					break
				}
			}
			if !found {
				fmt.Println("User not found")
			}
		case "4":
			username := readInput(reader, "Username: ")
			found := false
			for index := range accounts {
				if accounts[index].Username == username {
					found = true
					accounts = append(accounts[:index], accounts[index+1:]...)
					save()
					break
				}
			}
			if !found {
				fmt.Println("User not found")
			}
		case "5":
			return
		default:
			fmt.Println("Invalid choice")
		}
	}
}
