// vault/repo_postgres.go
package vault

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var validTable = regexp.MustCompile(`^[A-Za-z0-9_\\.]+$`)

type SecretRepository interface {
	GetSecret(ctx context.Context, key string) (*SecretRecord, error)
}

type PostgresSecretRepository struct {
	db    *gorm.DB
	table string
	cache *TTLCache[*SecretRecord]
}

func (p *PostgresSecretRepository) SetDB(db *gorm.DB) { p.db = db }

func NewPostgresSecretRepository(dsn, table string) (*PostgresSecretRepository, error) {
	return NewGormSecretRepository(postgres.Open(dsn), table)
}

func NewGormSecretRepository(dialector gorm.Dialector, table string) (*PostgresSecretRepository, error) {
	if !validTable.MatchString(table) {
		return nil, fmt.Errorf("invalid table name: %s", table)
	}
	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return &PostgresSecretRepository{
		db: db, table: table,
		cache: NewTTLCache[*SecretRecord](4096, time.Minute),
	}, nil
}

func (r *PostgresSecretRepository) GetSecret(ctx context.Context, key string) (*SecretRecord, error) {
	if rec, ok := r.cache.Get(key); ok && rec != nil {
		return rec, nil
	}
	var sec SecretRecord

	tx := r.db.WithContext(ctx).
		Table(r.table).
		Where("key = ?", key)

	if err := tx.First(&sec).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("not found, %v", err)
		}
		return nil, err
	}
	r.cache.Set(key, &sec)
	return &sec, nil
}
