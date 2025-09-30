package vault

import (
	"context"
	"sync"
)

type InMemoryRepo struct {
	mu   sync.RWMutex
	data map[string]*SecretRecord // by composite key (Key)
}

func NewInMemoryRepo() *InMemoryRepo {
	return &InMemoryRepo{data: make(map[string]*SecretRecord)}
}

func (r *InMemoryRepo) Put(rec *SecretRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[rec.Key] = rec
}

func (r *InMemoryRepo) GetSecret(ctx context.Context, key string) (*SecretRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if v, ok := r.data[key]; ok {
		return v, nil
	}
	return nil, nil
}
