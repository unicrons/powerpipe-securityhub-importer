package utils

import (
	"crypto/sha512"
	"encoding/base64"
)

func HashSha512(input string) string {
	h := sha512.New()
	h.Write([]byte(input))
	hashBytes := h.Sum(nil)[:9]
	return base64.StdEncoding.EncodeToString([]byte(hashBytes))
}
