package vault_test

import (
	"context"
	"testing"
	"time"

	"github.com/grasp-labs/ds-vault-go-sdk/internal/fakes"
	vault "github.com/grasp-labs/ds-vault-go-sdk/vault"

	"gorm.io/driver/sqlite"
)

func TestPostgresSecretRepository_WithSQLite(t *testing.T) {
	t.Parallel()

	// Shared in-memory DB name so multiple opens see the same DB
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"

	// 1) Migrate & seed using a regular *gorm.DB*
	db := fakes.NewDB(t, dsn)

	seed := vault.SecretRecord{
		Key:   "svc/api/creds",
		Value: "super-secret",
	}
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

	// (Optional) tighten cache TTL for determinism (if you add a setter)
	_ = time.Minute

	// 3) Exercise GetSecret (hits SQLite), then hit cache on 2nd call
	got, err := repo.GetSecret(context.Background(), seed.Key)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got == nil || got.Key != seed.Key || got.Value != seed.Value {
		t.Fatalf("unexpected record: %+v", got)
	}

	got2, err := repo.GetSecret(context.Background(), seed.Key)
	if err != nil {
		t.Fatalf("GetSecret (cached): %v", err)
	}
	if got2 == nil || got2.Key != seed.Key {
		t.Fatalf("unexpected cached record: %+v", got2)
	}
}
