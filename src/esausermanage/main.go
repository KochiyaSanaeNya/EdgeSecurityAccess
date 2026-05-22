package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Account struct {
	Username string
	Password string
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 65536, 4, 32)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s", b64Salt, b64Hash), nil
}

func verifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	otherHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(hash)))
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

func loadAccounts(path string) ([]Account, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var accounts []Account
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		accounts = append(accounts, Account{
			Username: strings.TrimSpace(parts[0]),
			Password: strings.TrimSpace(parts[1]),
		})
	}
	return accounts, scanner.Err()
}

func saveAccounts(path string, accounts []Account) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, acc := range accounts {
		line := fmt.Sprintf("%s:%s\n", acc.Username, acc.Password)
		if _, err := writer.WriteString(line); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func printAccounts(accounts []Account) {
	fmt.Println("\n==================== User List ====================")
	fmt.Printf("%-5s %-20s %-25s\n", "Index", "Username", "Password Hash (Argon2)")
	for i, acc := range accounts {
		passShort := acc.Password
		if len(passShort) > 25 {
			passShort = passShort[:22] + "..."
		}
		fmt.Printf("%-5d %-20s %-25s\n", i+1, acc.Username, passShort)
	}
	fmt.Println("===================================================")
}

func readInput(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	var path string
	var accounts []Account
	var err error

	for {
		path = readInput(reader, "Enter the absolute path of the configuration file: ")
		if path == "" {
			fmt.Println("Path cannot be empty.")
			continue
		}
		accounts, err = loadAccounts(path)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("File does not exist. A new file will be created upon saving.")
				accounts = []Account{}
				break
			}
			fmt.Printf("Error loading file: %v\n", err)
			continue
		}
		break
	}

	for {
		printAccounts(accounts)
		fmt.Println("\nMenu:")
		fmt.Println("1. Create User")
		fmt.Println("2. Find/Verify User")
		fmt.Println("3. Update User Password")
		fmt.Println("4. Delete User")
		fmt.Println("5. Exit")
		choice := readInput(reader, "Enter choice (1-5): ")

		switch choice {
		case "1":
			username := readInput(reader, "Enter Username: ")
			if username == "" {
				fmt.Println("Error: Username cannot be empty.")
				continue
			}
			exists := false
			for _, acc := range accounts {
				if acc.Username == username {
					exists = true
					break
				}
			}
			if exists {
				fmt.Println("Error: Username already exists.")
				continue
			}
			password := readInput(reader, "Enter Password: ")
			if password == "" {
				fmt.Println("Error: Password cannot be empty.")
				continue
			}

			encrypted, err := hashPassword(password)
			if err != nil {
				fmt.Printf("Encryption error: %v\n", err)
				continue
			}

			accounts = append(accounts, Account{
				Username: username,
				Password: encrypted,
			})
			if err := saveAccounts(path, accounts); err != nil {
				fmt.Printf("Error saving: %v\n", err)
			} else {
				fmt.Println("User created and saved successfully.")
			}

		case "2":
			search := readInput(reader, "Enter Username to find: ")
			found := false
			for _, acc := range accounts {
				if acc.Username == search {
					fmt.Printf("\nFound User:\nUsername: %s\nPassword Hash: %s\n", acc.Username, acc.Password)

					verifyOpt := readInput(reader, "Do you want to verify a plain password against this hash? (y/n): ")
					if strings.ToLower(verifyOpt) == "y" {
						plainPass := readInput(reader, "Enter plain password: ")
						match, err := verifyPassword(plainPass, acc.Password)
						if err != nil {
							fmt.Printf("Verification error: %v\n", err)
						} else if match {
							fmt.Println("Success: Password matches!")
						} else {
							fmt.Println("Failed: Password mismatch.")
						}
					}
					found = true
					break
				}
			}
			if !found {
				fmt.Println("User not found.")
			}

		case "3":
			search := readInput(reader, "Enter Username to update: ")
			index := -1
			for i, acc := range accounts {
				if acc.Username == search {
					index = i
					break
				}
			}
			if index == -1 {
				fmt.Println("Username not found.")
				continue
			}

			newPassword := readInput(reader, "Enter New Password: ")
			if newPassword == "" {
				fmt.Println("Password cannot be empty. Update aborted.")
				continue
			}

			encrypted, err := hashPassword(newPassword)
			if err != nil {
				fmt.Printf("Encryption error: %v\n", err)
				continue
			}

			accounts[index].Password = encrypted
			if err := saveAccounts(path, accounts); err != nil {
				fmt.Printf("Error saving: %v\n", err)
			} else {
				fmt.Println("User password updated successfully.")
			}

		case "4":
			search := readInput(reader, "Enter Username to delete: ")
			index := -1
			for i, acc := range accounts {
				if acc.Username == search {
					index = i
					break
				}
			}
			if index == -1 {
				fmt.Println("Username not found.")
				continue
			}

			accounts = append(accounts[:index], accounts[index+1:]...)
			if err := saveAccounts(path, accounts); err != nil {
				fmt.Printf("Error saving: %v\n", err)
			} else {
				fmt.Println("User deleted successfully.")
			}

		case "5":
			fmt.Println("Exiting program.")
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

func init() {
	log.SetOutput(io.Discard)
}
