package vault_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	vault "github.com/grasp-labs/ds-vault-go-sdk/vault"

	fakes "github.com/grasp-labs/ds-vault-go-sdk/internal/fakes"
)

type stubRepo struct {
	rec   *vault.SecretRecord
	err   error
	calls int
}

func (s *stubRepo) GetSecret(_ context.Context, key string) (*vault.SecretRecord, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if s.rec != nil && s.rec.Key == key {
		return s.rec, nil
	}
	return nil, nil
}

func TestClient_GetSecret_FromSSM_AndCache(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tenantID := uuid.New()
	secretID := uuid.New()
	env := vault.EnvDev
	key := vault.MakeKey(secretID, tenantID, string(vault.StoreAWSSSM), string(env), "ds", "vault")
	aad, encCtx := vault.MakeAADAndEncCtx(tenantID, key)

	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	ivB64, valueB64, tagB64, err := fakes.EncryptWithDEK(dek, []byte("p@ssw0rd"), aad)
	require.NoError(t, err)

	kekKeyID := "arn:aws:kms:eu-north-1:111122223333:key/abcd"
	kmsFake := &fakes.KMS{
		Plaintext:    dek,
		ExpectEncCtx: encCtx,
		ExpectKeyID:  kekKeyID,
	}
	ssmFake := &fakes.SSM{
		Values: map[string]string{
			key: valueB64,
		},
	}

	kmsProv := vault.NewKMSProvider(kmsFake, 1024, 5*time.Minute)
	ssmProv := vault.NewSSMProvider(ssmFake, 1024, 5*time.Minute)

	rec := &vault.SecretRecord{
		ID:         secretID,
		TenantID:   tenantID,
		Key:        key,
		Store:      vault.StoreAWSSSM,
		Status:     vault.StatusActive,
		Version:    "v1",
		Value:      "",
		IV:         ivB64,
		Tag:        tagB64,
		WrappedDEK: base64.StdEncoding.EncodeToString([]byte("WRAPPED-DEK")),
		KEKKeyID:   kekKeyID,
		DEKAlg:     "AES-256-GCM",
		KEKAlg:     "AWS-KMS",
	}

	repo := &stubRepo{rec: rec}

	client := vault.NewClient(repo, kmsProv, ssmProv, time.Minute)

	pt, err := client.GetSecret(ctx, key)
	require.NoError(t, err)
	require.Equal(t, []byte("p@ssw0rd"), pt)
	require.Equal(t, 1, kmsFake.Calls)
	require.Equal(t, 1, ssmFake.Calls)

	pt2, err := client.GetSecret(ctx, key)
	require.NoError(t, err)
	require.Equal(t, []byte("p@ssw0rd"), pt2)
	require.Equal(t, 1, kmsFake.Calls)
	require.Equal(t, 1, ssmFake.Calls)
}

func TestClient_GetSecret_FromDB_AndCache(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tenantID := uuid.New()
	secretID := uuid.New()
	env := vault.EnvDev
	key := vault.MakeKey(secretID, tenantID, string(vault.StoreDSVault), string(env), "ds", "vault")
	aad, encCtx := vault.MakeAADAndEncCtx(tenantID, key)

	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	ivB64, valueB64, tagB64, err := fakes.EncryptWithDEK(dek, []byte("db-secret"), aad)
	require.NoError(t, err)

	kekKeyID := "arn:aws:kms:eu-north-1:111122223333:key/efgh"
	kmsFake := &fakes.KMS{
		Plaintext:    dek,
		ExpectEncCtx: encCtx,
		ExpectKeyID:  kekKeyID,
	}
	ssmFake := &fakes.SSM{Values: map[string]string{}}

	kmsProv := vault.NewKMSProvider(kmsFake, 1024, 5*time.Minute)
	ssmProv := vault.NewSSMProvider(ssmFake, 1024, 5*time.Minute)

	rec := &vault.SecretRecord{
		ID:         secretID,
		TenantID:   tenantID,
		Key:        key,
		Store:      vault.StoreDSVault,
		Status:     vault.StatusActive,
		Version:    "v1",
		Value:      valueB64,
		IV:         ivB64,
		Tag:        tagB64,
		WrappedDEK: "V1JBUFBFRA==",
		KEKKeyID:   kekKeyID,
		DEKAlg:     "AES-256-GCM",
		KEKAlg:     "AWS-KMS",
	}

	repo := &stubRepo{rec: rec}
	client := vault.NewClient(repo, kmsProv, ssmProv, time.Minute)

	pt, err := client.GetSecret(ctx, key)
	require.NoError(t, err)
	require.Equal(t, []byte("db-secret"), pt)
	require.Equal(t, 1, kmsFake.Calls)
	require.Equal(t, 0, ssmFake.Calls)

	pt2, err := client.GetSecret(ctx, key)
	require.NoError(t, err)
	require.Equal(t, []byte("db-secret"), pt2)
	require.Equal(t, 1, kmsFake.Calls)
	require.Equal(t, 0, ssmFake.Calls)
}
