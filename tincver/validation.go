package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	allowedTimeSkew     = 30 * time.Second
	minIPv4MaskBits     = 24
	minIPv6MaskBits     = 64
	minNonceLength      = 16
	maxNonceLength      = 64
	maxTimestampLength  = 19
	maxUsernameLength   = 32
	maxTincNameLength   = 64
	minPasswordLength   = 6
	maxPasswordLength   = 256
	tincPublicKeyLength = 32
)

var (
	tincPubKeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=?$`)
	tincNameRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	usernameRe   = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
)

type ValidationError struct {
	Field   string
	Code    string
	Message string
	Status  int
}

func (e *ValidationError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "validation failed: " + e.Field + ":" + e.Code
}

func NewValidationError(field, code string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Code:    code,
		Message: validationMessage(field, code),
		Status:  validationStatus(field, code),
	}
}

func validationStatus(field, code string) int {
	switch field + ":" + code {
	case "request:too_large":
		return http.StatusRequestEntityTooLarge
	case "request:invalid_form":
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

func validationMessage(field, code string) string {
	switch field + ":" + code {
	case "request:too_large":
		return "request body too large"
	case "request:invalid_form":
		return "request has invalid form"
	case "request:nil":
		return "request is nil"
	case "username:missing":
		return "username is required"
	case "username:too_long":
		return "username exceeds maximum length"
	case "username:invalid_format":
		return "username has invalid characters"
	case "password:missing":
		return "password is required"
	case "password:too_short":
		return "password is too short"
	case "password:too_long":
		return "password exceeds maximum length"
	case "password:invalid_utf8":
		return "password must be valid UTF-8"
	case "password:invalid_chars":
		return "password contains control characters"
	case "pubkey:missing":
		return "tinc public key is required"
	case "pubkey:invalid_format":
		return "tinc public key has invalid format"
	case "pubkey:invalid_utf8":
		return "tinc public key must be valid UTF-8"
	case "pubkey:invalid_chars":
		return "tinc public key contains invalid characters"
	case "pubkey:invalid_base64":
		return "tinc public key must be valid base64"
	case "pubkey:invalid_length":
		return "tinc public key has invalid length"
	case "tinc_name:missing":
		return "tinc node name is required"
	case "tinc_name:too_long":
		return "tinc node name exceeds maximum length"
	case "tinc_name:invalid_format":
		return "tinc node name has invalid format"
	case "nonce:missing":
		return "nonce is required"
	case "nonce:too_short":
		return "nonce is too short"
	case "nonce:too_long":
		return "nonce is too long"
	case "nonce:invalid_chars":
		return "nonce has invalid characters"
	case "timestamp:missing":
		return "timestamp is required"
	case "timestamp:invalid_format":
		return "timestamp has invalid format"
	case "timestamp:invalid_utf8":
		return "timestamp must be valid UTF-8"
	case "timestamp:invalid_chars":
		return "timestamp contains invalid characters"
	case "timestamp:skew":
		return "timestamp outside allowed skew"
	case "signature:missing":
		return "signature is required"
	case "signature:length":
		return "signature has invalid length"
	case "signature:invalid_format":
		return "signature must be valid hex"
	case "signature:invalid_utf8":
		return "signature must be valid UTF-8"
	case "signature:invalid_chars":
		return "signature contains invalid characters"
	case "allowed_ip:missing":
		return "allowed IP is required"
	case "allowed_ip:invalid_format":
		return "allowed IP has invalid format"
	case "allowed_ip:ipv4_too_wide":
		return "allowed IPv4 range is too wide"
	case "allowed_ip:ipv6_too_wide":
		return "allowed IPv6 range is too wide"
	default:
		return ""
	}
}

type AuthRequest struct {
	Username     string
	Password     string
	PubKey       string
	TimestampRaw string
	Timestamp    int64
	Nonce        string
	Signature    string
}

func ParseAuthRequest(w http.ResponseWriter, r *http.Request, now time.Time) (*AuthRequest, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, NewValidationError("request", "too_large")
		}
		return nil, NewValidationError("request", "invalid_form")
	}
	username, err := sanitizeValue("username", r.PostFormValue("username"))
	if err != nil {
		return nil, err
	}
	pubKey, err := sanitizeValue("pubkey", r.PostFormValue("pubkey"))
	if err != nil {
		return nil, err
	}
	nonce, err := sanitizeValue("nonce", r.PostFormValue("nonce"))
	if err != nil {
		return nil, err
	}
	sig, err := sanitizeValue("signature", r.PostFormValue("signature"))
	if err != nil {
		return nil, err
	}
	tsRaw, err := sanitizeValue("timestamp", r.PostFormValue("timestamp"))
	if err != nil {
		return nil, err
	}
	password, err := sanitizePassword(r.PostFormValue("password"))
	if err != nil {
		return nil, err
	}
	if err := requireSingleFormValues(
		r,
		"username",
		"password",
		"pubkey",
		"timestamp",
		"nonce",
		"signature",
	); err != nil {
		return nil, err
	}
	sig = strings.ToLower(sig)
	req := &AuthRequest{
		Username:     username,
		Password:     password,
		PubKey:       pubKey,
		TimestampRaw: tsRaw,
		Nonce:        nonce,
		Signature:    sig,
	}
	if err := ValidateAuthRequest(req, now); err != nil {
		return nil, err
	}
	return req, nil
}

func requireSingleFormValues(r *http.Request, fields ...string) error {
	for _, field := range fields {
		if len(r.PostForm[field]) != 1 {
			return NewValidationError(field, "invalid_format")
		}
	}
	return nil
}

func ValidateAuthRequest(req *AuthRequest, now time.Time) error {
	if req == nil {
		return NewValidationError("request", "nil")
	}
	if err := ValidateUsername(req.Username); err != nil {
		return err
	}
	if err := ValidatePassword(req.Password); err != nil {
		return err
	}
	if err := ValidatePubKey(req.PubKey); err != nil {
		return err
	}
	if err := ValidateSignature(req.Signature); err != nil {
		return err
	}
	if err := ValidateNonce(req.Nonce); err != nil {
		return err
	}
	ts, err := ValidateTimestamp(req.TimestampRaw, now)
	if err != nil {
		return err
	}
	req.Timestamp = ts
	return nil
}

func ValidateTimestamp(tsStr string, now time.Time) (int64, error) {
	s := strings.TrimSpace(tsStr)
	if s == "" {
		return 0, NewValidationError("timestamp", "missing")
	}
	if len(s) > maxTimestampLength {
		return 0, NewValidationError("timestamp", "invalid_format")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, NewValidationError("timestamp", "invalid_format")
		}
	}
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, NewValidationError("timestamp", "invalid_format")
	}
	if delta := now.Sub(time.Unix(ts, 0)); delta > allowedTimeSkew || delta < -allowedTimeSkew {
		return 0, NewValidationError("timestamp", "skew")
	}
	return ts, nil
}

func ValidateUsername(username string) error {
	if strings.TrimSpace(username) == "" {
		return NewValidationError("username", "missing")
	}
	if len(username) > maxUsernameLength {
		return NewValidationError("username", "too_long")
	}
	if !usernameRe.MatchString(username) {
		return NewValidationError("username", "invalid_format")
	}
	return nil
}

func ValidatePassword(password string) error {
	if password == "" {
		return NewValidationError("password", "missing")
	}
	if len(password) < minPasswordLength {
		return NewValidationError("password", "too_short")
	}
	if len(password) > maxPasswordLength {
		return NewValidationError("password", "too_long")
	}
	if !utf8.ValidString(password) {
		return NewValidationError("password", "invalid_utf8")
	}
	if containsControlRunes(password) {
		return NewValidationError("password", "invalid_chars")
	}
	return nil
}

func ValidatePubKey(pubkey string) error {
	s := strings.TrimSpace(pubkey)
	if s == "" {
		return NewValidationError("pubkey", "missing")
	}
	if !tincPubKeyRe.MatchString(s) {
		return NewValidationError("pubkey", "invalid_format")
	}
	decodeValue := s
	if len(decodeValue)%4 != 0 {
		decodeValue += strings.Repeat("=", 4-len(decodeValue)%4)
	}
	decoded, err := base64.StdEncoding.DecodeString(decodeValue)
	if err != nil {
		return NewValidationError("pubkey", "invalid_base64")
	}
	if len(decoded) != tincPublicKeyLength {
		return NewValidationError("pubkey", "invalid_length")
	}
	return nil
}

func ValidateTincName(name string) error {
	s := strings.TrimSpace(name)
	if s == "" {
		return NewValidationError("tinc_name", "missing")
	}
	if len(s) > maxTincNameLength {
		return NewValidationError("tinc_name", "too_long")
	}
	if !tincNameRe.MatchString(s) {
		return NewValidationError("tinc_name", "invalid_format")
	}
	return nil
}

func ValidateSignature(signature string) error {
	s := strings.TrimSpace(signature)
	if s == "" {
		return NewValidationError("signature", "missing")
	}
	if len(s) != 64 {
		return NewValidationError("signature", "length")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return NewValidationError("signature", "invalid_format")
	}
	return nil
}

func ValidateNonce(nonce string) error {
	s := strings.TrimSpace(nonce)
	if s == "" {
		return NewValidationError("nonce", "missing")
	}
	if len(s) < minNonceLength {
		return NewValidationError("nonce", "too_short")
	}
	if len(s) > maxNonceLength {
		return NewValidationError("nonce", "too_long")
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return NewValidationError("nonce", "invalid_chars")
	}
	return nil
}

func ValidateAllowedIP(value string) error {
	s := strings.TrimSpace(value)
	if s == "" {
		return NewValidationError("allowed_ip", "missing")
	}
	if ip := net.ParseIP(s); ip != nil {
		return nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil || n == nil {
		return NewValidationError("allowed_ip", "invalid_format")
	}
	ones, bits := n.Mask.Size()
	if bits == 32 {
		if ones >= minIPv4MaskBits {
			return nil
		}
		return NewValidationError("allowed_ip", "ipv4_too_wide")
	}
	if bits == 128 {
		if ones >= minIPv6MaskBits {
			return nil
		}
		return NewValidationError("allowed_ip", "ipv6_too_wide")
	}
	return NewValidationError("allowed_ip", "invalid_format")
}

func ValidatePeerIP(value string) error {
	s := strings.TrimSpace(value)
	if s == "" {
		return NewValidationError("allowed_ip", "missing")
	}
	if ip := net.ParseIP(s); ip != nil {
		if strings.Contains(s, "/") {
			return NewValidationError("allowed_ip", "invalid_format")
		}
		return nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil || n == nil {
		return NewValidationError("allowed_ip", "invalid_format")
	}
	ones, bits := n.Mask.Size()
	if bits == 32 {
		if ones == 32 {
			return nil
		}
		return NewValidationError("allowed_ip", "ipv4_too_wide")
	}
	if bits == 128 {
		if ones == 128 {
			return nil
		}
		return NewValidationError("allowed_ip", "ipv6_too_wide")
	}
	return NewValidationError("allowed_ip", "invalid_format")
}

func NormalizePeerIP(value string) (string, error) {
	if err := ValidatePeerIP(value); err != nil {
		return "", err
	}
	s := strings.TrimSpace(value)
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil || n == nil {
		return "", NewValidationError("allowed_ip", "invalid_format")
	}
	_, bits := n.Mask.Size()
	if bits == 32 {
		return ip.To4().String() + "/32", nil
	}
	return ip.String() + "/128", nil
}

func ValidatePeer(conf *upconf) error {
	if conf == nil {
		return NewValidationError("request", "nil")
	}
	if err := ValidateTincName(conf.nodename); err != nil {
		return err
	}
	if conf.status {
		if strings.TrimSpace(conf.userpublic) == "" {
			return NewValidationError("pubkey", "missing")
		}
		if err := ValidatePubKey(conf.userpublic); err != nil {
			return err
		}
		if err := ValidatePeerIP(conf.userip); err != nil {
			return err
		}
	}
	return nil
}

func sanitizeValue(field, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", NewValidationError(field, "missing")
	}
	if !utf8.ValidString(trimmed) {
		return "", NewValidationError(field, "invalid_utf8")
	}
	if containsUnsafeRunes(trimmed) {
		return "", NewValidationError(field, "invalid_chars")
	}
	return trimmed, nil
}

func sanitizePassword(value string) (string, error) {
	if value == "" {
		return "", NewValidationError("password", "missing")
	}
	if len(value) < minPasswordLength {
		return "", NewValidationError("password", "too_short")
	}
	if len(value) > maxPasswordLength {
		return "", NewValidationError("password", "too_long")
	}
	if !utf8.ValidString(value) {
		return "", NewValidationError("password", "invalid_utf8")
	}
	if containsControlRunes(value) {
		return "", NewValidationError("password", "invalid_chars")
	}
	return value, nil
}

func containsUnsafeRunes(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

func containsControlRunes(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return true
		}
	}
	return false
}
