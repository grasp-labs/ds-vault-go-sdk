# ds-vault-go-sdk — SDK for the DS Vault service in Go

![Build](https://github.com/grasp-labs/ds-vault-go-sdk/actions/workflows/ci.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/grasp-labs/ds-vault-go-sdk)](https://goreportcard.com/report/github.com/grasp-labs/ds-vault-go-sdk)
[![codecov](https://codecov.io/gh/grasp-labs/ds-vault-go-sdk/branch/main/graph/badge.svg)](https://codecov.io/gh/grasp-labs/ds-vault-go-sdk)
[![Latest tag](https://img.shields.io/github/v/tag/grasp-labs/ds-vault-go-sdk?sort=semver)](https://github.com/grasp-labs/ds-vault-go-sdk/tags)
![License](https://img.shields.io/github/license/grasp-labs/ds-vault-go-sdk?cacheSeconds=60)

DS Vault Go SDK

High-level client for fetching secrets backed by Postgres (metadata), AWS KMS (DEK unwrap), and AWS SSM (ciphertext).

**The SDK includes a built-in TTL cache for repositories and and keys. Using cache greatly reduce cost and latency.**

## Why the cache matters (a lot)

- **Latency**: KMS decrypts and SSM GetParameter calls each add network hops. Without caching, every secret read can incur tens to hundreds of milliseconds.

- **Cost**: KMS and SSM are metered. Replaying decrypt/parameter calls for the same secret across requests quickly adds up.

- **Throughput**: Caching avoids hot-path bottlenecks under load.

**Bottom line**: Create a single Client and keep it for the lifetime of your app. Don’t rebuild it per request, per handler, or per job.

## Install

```bash
go get github.com/grasp-labs/ds-vault-go-sdk@latest
```

Latest

```bash
go get github.com/grasp-labs/ds-vault-go-sdk@latest
```

## Quickstart (singleton client)

Initialize once at process start (or in your DI container) and reuse everywhere.

```go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	vault "github.com/grasp-labs/ds-vault-go-sdk/vault"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func main() {
	ctx := context.Background()

	// --- Providers
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil { panic(err) }
	kmsProv := vault.NewKMSProvider(kms.NewFromConfig(awsCfg), 1024, 5*time.Minute)
	ssmProv := vault.NewSSMProvider(ssm.NewFromConfig(awsCfg), 1024, 5*time.Minute)

	// --- Repository (Postgres)
	dsn := os.Getenv("DSVAULT_PG_DSN") // e.g. postgres://user:pass@host:5432/db?sslmode=require
	repo, err := vault.NewPostgresSecretRepository(dsn, "public.secrets")
	if err != nil { panic(err) }

	// --- Singleton client with plaintext cache (default 1m if <=0)
	client := vault.NewClient(repo, kmsProv, ssmProv, 5*time.Minute)

	// Pass the *same* client everywhere (handlers, workers, etc.)
	_ = client
}
```

## Using the client

```go
// compose the key (helper ensures AAD/EncCtx line up across read paths)
pt, err := client.GetSecret(ctx, key)
if err != nil {
    // handle
}
fmt.Printf("secret = %s\n", pt)
```

⚠️ Do not instantiate Client per request. You will tank performance and pay more.

### Caching behavior

- The client uses an in-memory TTL cache for plaintext ([]byte).
- Default TTL is 1 minute (if you pass <=0). Configure via the constructor.
- Thread-safe; safe for concurrent use from many goroutines.
- Great for HTTP handlers, gRPC servers, workers, and CLIs.

### Tuning TTL

- Longer TTL → fewer KMS/SSM calls, lower latency/cost, slower to pick up rotations.
- Shorter TTL → faster rotation pickup, more upstream calls.

Typical production TTLs: `1–10 minutes`. For planned rotations, temporarily lower TTL or read a new key path (versioned key) so the cache key changes.

### Best practices

- ✅ Create one Client (app singleton) and reuse it.
- ✅ Keep the plaintext TTL cache enabled (don’t set TTL to 0).
- ✅ Consider warming the cache for your hottest secrets on startup.
- ✅ Version your secret keys (e.g., bump a vN in the key path) when rotating—this naturally bypasses old cache entries.
- ❌ Never construct Client inside request/handler functions.
- ❌ Don’t call KMS/SSM directly for secrets your app already fetched via the client—let the cache work.

### Thread safety

- Client, KMSProvider, SSMProvider, and the internal cache are safe for concurrent use.
- Share one instance across goroutines.

### Example: HTTP handler integration

```go
type App struct {
    Secrets *vault.Client
}

func (a *App) Handle(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    // Example composite key:
    pt, err := a.Secrets.GetSecret(ctx, someKey)
    if err != nil {
        http.Error(w, "secret fetch failed", 500)
        return
    }
    w.Write(pt)
}
```

Initialize App once (with a single Client) and register handlers.

### Key composition

Use the helper to guarantee AAD and KMS EncryptionContext match:

```go
key := vault.MakeKey(secretID, tenantID, string(vault.StoreAWSSSM), string(vault.EnvProd), "ds", "vault")
// Later, GetSecret(ctx, key)
```

### Testing locally (no AWS/PG required)

- For repository tests, you can use SQLite with the dialector-based constructor (if exposed) or a small fake repository.
- For providers, use the fakes in internal/fakes:
	- fakes.KMS (asserts exact EncryptionContext and KeyID)
	- fakes.SSM (in-memory map)
- These enable end-to-end client tests (repo → KMS unwrap → SSM/DB → decrypt → cache) without external services.

### Common pitfalls

- **Symptom**: High KMS/SSM bill & slow requests
  **Cause**: Recreating Client on every request ⇒ no cache hits.
  **Fix**: Initialize a single Client once and reuse.

- **Symptom**: App still sees old secret after rotation
  **Cause**: Cache TTL hasn’t elapsed or same key path reused.
  **Fix**: Lower TTL briefly or publish a new key (versioned path).

###API surface (short)

```go
type Client struct {
    // repo SecretRepository
    // kms  *KMSProvider
    // ssm  *SSMProvider
}

func NewClient(repo SecretRepository, kms *KMSProvider, ssm *SSMProvider, ptCacheTTL time.Duration) *Client
func (c *Client) GetSecret(ctx context.Context, key string) ([]byte, error)
```

See source for repository and provider constructors/options.

## TL;DR

- Create one SDK client and keep it alive.
- Let the plaintext cache do the heavy lifting.
- You’ll get lower latency, lower cost, and higher throughput.