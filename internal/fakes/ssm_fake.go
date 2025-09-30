package fakes

import (
	"context"
	"errors"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// SSM is a test double for vault.SSMAPI.
// Values holds parameter name -> value (string). WithDecryption is ignored.
type SSM struct {
	mu sync.Mutex

	Values map[string]string
	Err    error

	Calls    int
	LastName string
}

func (f *SSM) GetParameter(ctx context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.Err != nil {
		return nil, f.Err
	}
	if in == nil || in.Name == nil {
		return nil, errors.New("missing Name")
	}

	name := *in.Name
	f.Calls++
	f.LastName = name

	val, ok := f.Values[name]
	if !ok {
		return nil, errors.New("parameter not found")
	}
	return &ssm.GetParameterOutput{
		Parameter: &types.Parameter{
			Name:  &name,
			Value: &val,
		},
	}, nil
}
