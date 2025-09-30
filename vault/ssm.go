package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

type SSMAPI interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

type SSMProvider struct {
	ssm   SSMAPI
	cache *TTLCache[string]
}

func NewSSMProvider(c SSMAPI, cacheSize int, ttl time.Duration) *SSMProvider {
	return &SSMProvider{ssm: c, cache: NewTTLCache[string](cacheSize, ttl)}
}

// Returns the parameter value as a string (ciphertext base64 when store = aws_ssm).
func (p *SSMProvider) Get(ctx context.Context, name string) (string, error) {
	if v, ok := p.cache.Get(name); ok {
		return v, nil
	}
	t := true
	out, err := p.ssm.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           &name,
		WithDecryption: &t,
	})
	if err != nil {
		return "", fmt.Errorf("SSM GetParameter: %w", err)
	}
	val := *out.Parameter.Value
	p.cache.Set(name, val)
	return val, nil
}
