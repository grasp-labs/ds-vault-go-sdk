package fakes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// -------- tiny utils --------
func b64e(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// EncryptWithDEK encrypts plaintext using the provided 32-byte DEK (AES-256-GCM).
// Returns Base64(iv), Base64(ciphertext), Base64(tag).
func EncryptWithDEK(dek, plaintext, aad []byte) (string, string, string, error) {
	if len(dek) != 32 {
		return "", "", "", fmt.Errorf("DEK must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", err
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", "", "", err
	}

	ctWithTag := gcm.Seal(nil, iv, plaintext, aad)
	tagSize := gcm.Overhead()
	ct := ctWithTag[:len(ctWithTag)-tagSize]
	tag := ctWithTag[len(ctWithTag)-tagSize:]

	return b64e(iv), b64e(ct), b64e(tag), nil
}
