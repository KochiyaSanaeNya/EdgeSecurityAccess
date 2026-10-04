package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
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
)

const dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type argon2IDHash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	hash        []byte
}

var passwordVerifyTokens = make(chan struct{}, 2)

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
		defer func() { <-passwordVerifyTokens }()
	case <-ctx.Done():
		return false, ctx.Err()
	}
	computed := argon2.IDKey([]byte(password), parsed.salt, parsed.iterations, parsed.memory, parsed.parallelism, uint32(len(parsed.hash)))
	return subtle.ConstantTimeCompare(parsed.hash, computed) == 1, nil
}

func parseArgon2IDHash(encodedHash string) (*argon2IDHash, error) {
	parts := strings.Split(strings.TrimSpace(encodedHash), "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return nil, errors.New("invalid argon2id hash format")
	}
	memory, iterations, parallelism, err := parseArgon2Params(parts[3])
	if err != nil {
		return nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < argon2MinSaltLength || len(salt) > argon2MaxSaltLength {
		return nil, errors.New("invalid argon2id salt")
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) < argon2MinHashLength || len(hash) > argon2MaxHashLength {
		return nil, errors.New("invalid argon2id hash")
	}
	return &argon2IDHash{memory: memory, iterations: iterations, parallelism: parallelism, salt: salt, hash: hash}, nil
}

func parseArgon2Params(raw string) (uint32, uint32, uint8, error) {
	values := make(map[string]uint64, 3)
	for _, item := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(item, "=")
		if !ok || (key != "m" && key != "t" && key != "p") {
			return 0, 0, 0, errors.New("invalid argon2id parameters")
		}
		if _, exists := values[key]; exists {
			return 0, 0, 0, errors.New("invalid argon2id parameters")
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, 0, 0, errors.New("invalid argon2id parameters")
		}
		values[key] = parsed
	}
	if len(values) != 3 || values["m"] < argon2MinMemory || values["m"] > argon2MaxMemory || values["t"] < argon2MinIterations || values["t"] > argon2MaxIterations || values["p"] < argon2MinParallel || values["p"] > argon2MaxParallel {
		return 0, 0, 0, errors.New("invalid argon2id parameters")
	}
	return uint32(values["m"]), uint32(values["t"]), uint8(values["p"]), nil
}
