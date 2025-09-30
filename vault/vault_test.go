package vault_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/grasp-labs/ds-vault-go-sdk/internal/fakes"
	vault "github.com/grasp-labs/ds-vault-go-sdk/vault"
	"gorm.io/driver/sqlite"

	"crypto/aes"
	"crypto/cipher"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestGetSecret_AWSSSM_Envelope(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tenantID := uuid.New()
	secretID := uuid.New()
	store := vault.StoreAWSSSM
	env := vault.EnvDev

	key := vault.MakeKey(secretID, tenantID, string(store), string(env), "ds", "vault")

	// Envelope materials
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	aad, encCtx := vault.MakeAADAndEncCtx(tenantID, key)

	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	plaintext := []byte("p@ssw0rd")
	ctWithTag := gcm.Seal(nil, iv, plaintext, aad)
	ct, tag := ctWithTag[:len(ctWithTag)-16], ctWithTag[len(ctWithTag)-16:]

	seed := &vault.SecretRecord{
		ID:         secretID,
		TenantID:   tenantID,
		Issuer:     "issuer-x",
		Name:       "db_password",
		Version:    "v3",
		Status:     vault.StatusActive,
		Key:        key,
		Store:      vault.StoreAWSSSM, // ciphertext stored in SSM
		Value:      "",
		IV:         b64(iv),
		Tag:        b64(tag),
		WrappedDEK: b64(append([]byte("WRAPPED:"), dek...)),
		KEKKeyID:   "arn:aws:kms:eu-north-1:123456789012:key/abcd-ef",
		DEKAlg:     "AES256-GCM",
		KEKAlg:     "AWS-KMS",
	}

	// Shared in-memory DB name so multiple opens see the same DB
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"

	// 1) Migrate & seed using a regular *gorm.DB*
	db := fakes.NewDB(t, dsn)

	if err := db.Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 2) Create the repo via the REAL constructor (gorm.Open inside),
	//    just with sqlite dialector instead of postgres.
	tableName := "secret_records" // or "secrets" if your model overrides TableName()
	repo, err := vault.NewGormSecretRepository(sqlite.Open(dsn), tableName)
	if err != nil {
		t.Fatalf("NewGormSecretRepository: %v", err)
	}

	ssm := &fakes.SSM{
		Values: map[string]string{
			key: b64(ct), // ciphertext (no tag) lives in SSM
		},
	}

	kmsFake := &fakes.KMS{
		Plaintext:    dek,
		ExpectEncCtx: encCtx,
		ExpectKeyID:  seed.KEKKeyID,
	}

	// Providers + client
	kmsProv := vault.NewKMSProvider(kmsFake, 1024, 5*time.Minute)
	ssmProv := vault.NewSSMProvider(ssm, 1024, 5*time.Minute)
	client := vault.NewClient(repo, kmsProv, ssmProv, time.Minute)

	// --- Act
	got, err := client.GetSecret(ctx, key)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)

	// KMS called exactly once; SSM called once
	require.Equal(t, 1, kmsFake.Calls)
	require.Equal(t, 1, ssm.Calls)

	// Second call hits plaintext cache (no extra KMS/SSM)
	got2, err := client.GetSecret(ctx, key)
	require.NoError(t, err)
	require.Equal(t, plaintext, got2)
	require.Equal(t, 1, kmsFake.Calls)
	require.Equal(t, 1, ssm.Calls)
}
