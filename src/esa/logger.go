package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"strings"
	"time"
)

type logFields map[string]interface{}

func logJSON(level, msg string, fields logFields) {
	entry := make(logFields, len(fields)+3)
	for k, v := range fields {
		if s, ok := v.(string); ok {
			entry[k] = sanitizeLogValue(s)
		} else {
			entry[k] = v
		}
	}
	entry["ts"] = time.Now().UTC().Format(time.RFC3339)
	entry["level"] = level
	entry["msg"] = msg

	b, err := json.Marshal(entry)
	if err != nil {
		log.Printf("log marshal failed: %v", err)
		return
	}
	log.Println(string(b))
}

func sanitizeLogValue(s string) string {
	if s == "" {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

func pubKeyHash(pubkey string) string {
	if pubkey == "" {
		return ""
	}
	h := sha256.Sum256([]byte(pubkey))
	return hex.EncodeToString(h[:8])
}
