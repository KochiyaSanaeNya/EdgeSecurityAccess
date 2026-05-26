package main

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2MinMemory     = 32 * 1024
	argon2MaxMemory     = 256 * 1024
	argon2MinIterations = 1
	argon2MaxIterations = 10
	argon2MinParallel   = 1
	argon2MaxParallel   = 8
)

func verifyPassword(password, encodedHash string) (bool, error) {
	encodedHash = strings.TrimSpace(encodedHash)
	encodedHash = strings.TrimRight(encodedHash, "\r\n")
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
	if memory < argon2MinMemory || memory > argon2MaxMemory {
		return false, errors.New("invalid argon2 memory")
	}
	if iterations < argon2MinIterations || iterations > argon2MaxIterations {
		return false, errors.New("invalid argon2 iterations")
	}
	if parallelism < argon2MinParallel || parallelism > argon2MaxParallel {
		return false, errors.New("invalid argon2 parallelism")
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

/*func deriveAuthKey(password, encodedHash string) ([]byte, error) {
	encodedHash = strings.TrimSpace(encodedHash)
	encodedHash = strings.TrimRight(encodedHash, "\r\n")
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, errors.New("invalid hash format")
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return nil, err
	}
	if memory < argon2MinMemory || memory > argon2MaxMemory {
		return nil, errors.New("invalid argon2 memory")
	}
	if iterations < argon2MinIterations || iterations > argon2MaxIterations {
		return nil, errors.New("invalid argon2 iterations")
	}
	if parallelism < argon2MinParallel || parallelism > argon2MaxParallel {
		return nil, errors.New("invalid argon2 parallelism")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}

	key := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, 32)
	return key, nil
}
*/
