package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type KMSAPI interface {
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type KMSProvider struct {
	kms   KMSAPI
	cache *TTLCache[[]byte]
}

func NewKMSProvider(k KMSAPI, cacheSize int, ttl time.Duration) *KMSProvider {
	return &KMSProvider{kms: k, cache: NewTTLCache[[]byte](cacheSize, ttl)}
}

func encCtxJSON(ctx map[string]string) string {
	if ctx == nil {
		return "{}"
	}
	// stable key order
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sb := strings.Builder{}
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		b, _ := json.Marshal(ctx[k])
		sb.WriteString(fmt.Sprintf("%q:%s", k, string(b)))
	}
	sb.WriteByte('}')
	return sb.String()
}

func (p *KMSProvider) cacheKey(wrappedB64 string, encCtx map[string]string, keyID string) string {
	return wrappedB64 + "|" + encCtxJSON(encCtx) + "|" + keyID
}

func (p *KMSProvider) DecryptDEK(ctx context.Context, wrappedB64 string, encCtx map[string]string, keyID string) ([]byte, error) {
	ck := p.cacheKey(wrappedB64, encCtx, keyID)
	if dek, ok := p.cache.Get(ck); ok {
		return dek, nil
	}
	blob, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		return nil, fmt.Errorf("wrapped_dek base64: %w", err)
	}
	in := &kms.DecryptInput{
		CiphertextBlob: blob,
		EncryptionContext: func() map[string]string {
			if encCtx == nil {
				return nil
			}
			return encCtx
		}(),
	}
	if keyID != "" {
		in.KeyId = &keyID
	}
	out, err := p.kms.Decrypt(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("KMS Decrypt: %w", err)
	}
	p.cache.Set(ck, out.Plaintext)
	return out.Plaintext, nil
}
