package vault

import (
	"context"
	"fmt"
	"time"
)

// Client pulls secret metadata from the repository, retrieves ciphertext
// (from SSM if configured), unwraps the DEK via KMS, and decrypts the secret.
// Decrypted plaintexts are memoized in a small in-memory TTL cache to avoid
// repeated KMS/SSM calls.
//
// Flow on GetSecret:
//  1. Check plaintext cache; if present and valid, return immediately.
//  2. Load SecretRecord from the SecretRepository by composite key.
//  3. Derive AAD and KMS EncryptionContext using MakeAADAndEncCtx(rec.TenantID, rec.Key).
//  4. Unwrap the DEK with KMS (Decrypt using rec.WrappedDEK and rec.KEKKeyID).
//  5. If Store==StoreAWSSSM, fetch Base64(ciphertext) from SSM by rec.Key;
//     otherwise use rec.Value from the DB. IV and Tag are stored in the record.
//  6. AES-GCM decrypt using (DEK, IV, Tag, AAD), cache plaintext under key, return.
//
// Concurrency: Client is safe for concurrent use as long as the injected
// providers and repository are safe; the internal plaintext cache is
// guarded and TTL-based.
// Errors: Any underlying repository / KMS / SSM / crypto error bubbles up.
type Client struct {
	repo SecretRepository
	kms  *KMSProvider
	ssm  *SSMProvider

	plaintextCache *TTLCache[[]byte]
}

// NewClient builds a Client from the given repository and providers.
// ptCacheTTL controls how long decrypted plaintexts are retained in the
// in-memory cache. If ptCacheTTL <= 0, a default of one minute is used.
// kms and ssm must be non-nil; this function panics if either is nil.
func NewClient(repo SecretRepository, kms *KMSProvider, ssm *SSMProvider, ptCacheTTL time.Duration) *Client {
	if kms == nil {
		panic("kms provider is required")
	}
	if ssm == nil {
		panic("ssm provider is required")
	}
	if ptCacheTTL <= 0 {
		ptCacheTTL = time.Minute
	}
	return &Client{
		repo:           repo,
		kms:            kms,
		ssm:            ssm,
		plaintextCache: NewTTLCache[[]byte](4096, ptCacheTTL),
	}
}

// GetSecret returns the decrypted plaintext for the given composite key.
// It first checks the in-memory plaintext cache. On miss, it loads the
// SecretRecord from the repository, unwraps the DEK via KMS using an exact
// EncryptionContext derived from the record, fetches ciphertext from SSM
// when Store==StoreAWSSSM (otherwise uses the DB value), decrypts using
// AES-GCM with AAD, caches the plaintext, and returns it.
func (c *Client) GetSecret(ctx context.Context, key string) ([]byte, error) {
	if pt, ok := c.plaintextCache.Get(key); ok {
		return pt, nil
	}
	rec, err := c.repo.GetSecret(ctx, key)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, fmt.Errorf("secret not found for key %q", key)
	}

	// AAD + KMS EncryptionContext from the record
	aad, encCtx := MakeAADAndEncCtx(rec.TenantID, rec.Key)

	// Unwrap DEK
	dek, err := c.kms.DecryptDEK(ctx, rec.WrappedDEK, encCtx, rec.KEKKeyID)
	if err != nil {
		return nil, err
	}

	// Get ciphertext (DB vs SSM)
	valueB64 := rec.Value
	if rec.Store == StoreAWSSSM {
		valueB64, err = c.ssm.Get(ctx, rec.Key)
		if err != nil {
			return nil, err
		}
	}

	pt, err := decryptAESGCM(dek, valueB64, rec.IV, rec.Tag, aad)
	if err != nil {
		return nil, err
	}
	c.plaintextCache.Set(key, pt)
	return pt, nil
}
