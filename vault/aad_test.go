package vault_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	vault "github.com/grasp-labs/ds-vault-go-sdk/vault"
	"github.com/stretchr/testify/assert"
)

func TestAAD(t *testing.T) {
	secretID := uuid.New()
	tenantID := uuid.New()
	store := "ds_vault"
	environment := "dev"
	domain := "ds"
	service := "vault"
	key := vault.MakeKey(secretID, tenantID, store, environment, domain, service)
	aadBytes, encCtx := vault.MakeAADAndEncCtx(tenantID, key)
	// Verify parts
	aadString := string(aadBytes)
	parts := strings.Split(aadString, "|")
	assert.Equal(t, len(parts), 2)
	strings.Contains(parts[0], tenantID.String())
	strings.Contains(parts[1], key)

	// Verify map
	value, ok := encCtx["tenant_id"]
	if !ok {
		t.Fatalf("failed to find key ´tenant_id´ in map")
	}
	assert.Equal(t, value, tenantID.String())
	value, ok = encCtx["key"]
	if !ok {
		t.Fatalf("failed to find key key in map")
	}
	assert.Equal(t, value, key)
}
