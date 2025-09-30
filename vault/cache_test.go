package vault_test

import (
	"testing"
	"time"

	vault "github.com/grasp-labs/ds-vault-go-sdk/vault"
	"github.com/stretchr/testify/assert"
)

func TestCache_TTL(t *testing.T) {
	ttl := 1 * time.Second
	record := vault.SecretRecord{
		Name: "test",
		Key:  "abc",
	}
	// New TTL cache storing SecretRecords, max 1024 bytes, expires after a second
	ttlCache := vault.NewTTLCache[*vault.SecretRecord](1024, ttl)
	ttlCache.Set(record.Key, &record)

	// Assert we can get
	r, ok := ttlCache.Get(record.Key)
	if !ok {
		t.Fatalf("expected cache hit")
	}
	assert.Equal(t, &record, r)

	// Sleep > ttl && assert cannot be found
	time.Sleep(2000 * time.Millisecond)
	got, ok := ttlCache.Get(record.Key)
	if ok {
		t.Fatalf("expected cache miss")
	}
	assert.Nil(t, got)

}
