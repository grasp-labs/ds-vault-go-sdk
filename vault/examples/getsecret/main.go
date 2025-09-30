package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/google/uuid"

	vault "github.com/grasp-labs/ds-vault-go-sdk/vault"
)

func main() {
	ctx := context.Background()

	// GORM repo
	repo, err := vault.NewPostgresSecretRepository(os.Getenv("DSVAULT_PG_DSN"), "public.secrets")
	if err != nil {
		panic(err)
	}

	// AWS providers
	awsCfg, _ := config.LoadDefaultConfig(ctx)
	kmsProv := vault.NewKMSProvider(kms.NewFromConfig(awsCfg), 1024, 5*time.Minute)
	ssmProv := vault.NewSSMProvider(ssm.NewFromConfig(awsCfg), 1024, 5*time.Minute)

	client := vault.NewClient(repo, kmsProv, ssmProv, time.Minute)

	// composite lookup key: /ds/vault/<store>/<secret_id>/<tenant_id>/<env>
	secretID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	tenantID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	key := vault.MakeKey(secretID, tenantID, string(vault.StoreAWSSSM), "prod", "ds", "vault")

	pt, err := client.GetSecret(ctx, key)
	if err != nil {
		panic(err)
	}
	fmt.Println("secret:", string(pt))
}
