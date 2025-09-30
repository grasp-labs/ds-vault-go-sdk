package vault

import "github.com/google/uuid"

// MakeAADEndEncCtx is a function creating Additional Authentication Data (AAD)
// and create encryption context - a set of non-secret that are cryptographically
// bound to encrypted data.
//
// Paramenters:
//
// TenantID: PK, uuid
// Key: Secret model key attribute
func MakeAADAndEncCtx(tenantID uuid.UUID, key string) ([]byte, map[string]string) {
	// AAD: single byte slice; order matters
	aad := []byte("tenant:" + tenantID.String() + "|key:" + key)
	// KMS EncryptionContext: must match exactly on decrypt
	encCtx := map[string]string{
		"tenant_id": tenantID.String(),
		"key":       key,
	}
	return aad, encCtx
}
