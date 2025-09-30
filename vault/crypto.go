package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func decryptAESGCM(dek []byte, valueB64, ivB64, tagB64 string, aad []byte) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(valueB64)
	if err != nil {
		return nil, fmt.Errorf("ciphertext base64: %w", err)
	}
	iv, err := base64.StdEncoding.DecodeString(ivB64)
	if err != nil {
		return nil, fmt.Errorf("iv base64: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(tagB64)
	if err != nil {
		return nil, fmt.Errorf("tag base64: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(iv) != g.NonceSize() {
		return nil, fmt.Errorf("bad iv size: %d", len(iv))
	}
	// Go writer stored tag separately; append before Open
	pt, err := g.Open(nil, iv, append(ct, tag...), aad)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return pt, nil
}
