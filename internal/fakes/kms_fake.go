package fakes

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// KMS is a test double for vault.KMSAPI.
// It returns Plaintext and records/validates inputs.
type KMS struct {
	mu sync.Mutex

	Plaintext    []byte
	ExpectEncCtx map[string]string // if non-nil, must match exactly
	ExpectKeyID  string            // if non-empty, must match
	Err          error             // if set, Decrypt returns this error

	Calls     int
	LastInput *kms.DecryptInput
}

func (f *KMS) Decrypt(ctx context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Calls++
	f.LastInput = in

	if f.Err != nil {
		return nil, f.Err
	}
	if f.ExpectKeyID != "" {
		if in.KeyId == nil || *in.KeyId != f.ExpectKeyID {
			return nil, errors.New("unexpected KeyId")
		}
	}
	if f.ExpectEncCtx != nil {
		if !reflect.DeepEqual(f.ExpectEncCtx, in.EncryptionContext) {
			return nil, errors.New("unexpected EncryptionContext")
		}
	}
	// CiphertextBlob is already bytes (provider base64-decodes before calling KMS).
	return &kms.DecryptOutput{Plaintext: f.Plaintext}, nil
}
