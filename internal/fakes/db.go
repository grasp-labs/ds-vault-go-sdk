package fakes

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	vault "github.com/grasp-labs/ds-vault-go-sdk/vault"
)

func NewDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&vault.SecretRecord{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return db
}
