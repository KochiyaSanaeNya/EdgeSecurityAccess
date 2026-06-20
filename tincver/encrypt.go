package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
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
	argon2MinSaltLength = 16
	argon2MaxSaltLength = 64
	argon2MinHashLength = 16
	argon2MaxHashLength = 64

	maxConcurrentPasswordVerifications = 2
)

const dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

var passwordVerifyTokens = make(chan struct{}, maxConcurrentPasswordVerifications)

type argon2IDHash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	hash        []byte
}

func ValidatePasswordHashFormat(encodedHash string) error {
	_, err := parseArgon2IDHash(encodedHash)
	return err
}

func verifyPassword(password, encodedHash string) (bool, error) {
	return verifyPasswordContext(context.Background(), password, encodedHash)
}

func verifyPasswordContext(ctx context.Context, password, encodedHash string) (bool, error) {
	parsed, err := parseArgon2IDHash(encodedHash)
	if err != nil {
		return false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case passwordVerifyTokens <- struct{}{}:
		defer func() {
			<-passwordVerifyTokens
		}()
	case <-ctx.Done():
		return false, ctx.Err()
	}

	otherHash := argon2.IDKey(
		[]byte(password),
		parsed.salt,
		parsed.iterations,
		parsed.memory,
		parsed.parallelism,
		uint32(len(parsed.hash)),
	)
	if subtle.ConstantTimeCompare(parsed.hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

func parseArgon2IDHash(encodedHash string) (*argon2IDHash, error) {
	encodedHash = strings.TrimSpace(encodedHash)
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" {
		return nil, errors.New("invalid argon2id hash format")
	}
	if parts[1] != "argon2id" {
		return nil, errors.New("unsupported password hash algorithm")
	}
	if parts[2] != "v=19" {
		return nil, errors.New("unsupported argon2id version")
	}

	memory, iterations, parallelism, err := parseArgon2Params(parts[3])
	if err != nil {
		return nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid argon2id salt: %w", err)
	}
	if len(salt) < argon2MinSaltLength || len(salt) > argon2MaxSaltLength {
		return nil, errors.New("invalid argon2id salt length")
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("invalid argon2id hash: %w", err)
	}
	if len(hash) < argon2MinHashLength || len(hash) > argon2MaxHashLength {
		return nil, errors.New("invalid argon2id hash length")
	}

	return &argon2IDHash{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		salt:        salt,
		hash:        hash,
	}, nil
}

func parseArgon2Params(raw string) (uint32, uint32, uint8, error) {
	params := strings.Split(raw, ",")
	if len(params) != 3 {
		return 0, 0, 0, errors.New("invalid argon2id parameters")
	}

	seen := make(map[string]bool, 3)
	values := make(map[string]uint64, 3)
	for _, param := range params {
		key, value, ok := strings.Cut(param, "=")
		if !ok || key == "" || value == "" || seen[key] {
			return 0, 0, 0, errors.New("invalid argon2id parameters")
		}
		switch key {
		case "m", "t", "p":
			parsed, err := parseStrictUint(value)
			if err != nil {
				return 0, 0, 0, errors.New("invalid argon2id parameters")
			}
			values[key] = parsed
			seen[key] = true
		default:
			return 0, 0, 0, errors.New("invalid argon2id parameters")
		}
	}
	if !seen["m"] || !seen["t"] || !seen["p"] {
		return 0, 0, 0, errors.New("invalid argon2id parameters")
	}

	memory := values["m"]
	iterations := values["t"]
	parallelism := values["p"]
	if memory < argon2MinMemory || memory > argon2MaxMemory {
		return 0, 0, 0, errors.New("invalid argon2 memory")
	}
	if iterations < argon2MinIterations || iterations > argon2MaxIterations {
		return 0, 0, 0, errors.New("invalid argon2 iterations")
	}
	if parallelism < argon2MinParallel || parallelism > argon2MaxParallel {
		return 0, 0, 0, errors.New("invalid argon2 parallelism")
	}
	return uint32(memory), uint32(iterations), uint8(parallelism), nil
}

func parseStrictUint(value string) (uint64, error) {
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("not an unsigned integer")
		}
	}
	return strconv.ParseUint(value, 10, 64)
}
