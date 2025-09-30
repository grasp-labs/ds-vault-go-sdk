package vault

import (
	"time"

	"github.com/google/uuid"
	"github.com/grasp-labs/ds-go-commonmodels/v2/commonmodels/types"
)

type Status string
type Store string
type Environment string

const (
	StatusActive    Status = "active"
	StatusDeleted   Status = "deleted"
	StatusSuspended Status = "suspended"
	StatusRejected  Status = "rejected"
	StatusDraft     Status = "draft"
	StatusClosed    Status = "closed"

	StoreAWSSSM  Store = "aws_ssm"
	StoreDSVault Store = "ds_vault"

	EnvDev  Environment = "dev"
	EnvProd Environment = "prod"
)

type SecretRecord struct {
	// Common
	ID          uuid.UUID
	TenantID    uuid.UUID
	OwnerID     *string
	Issuer      string
	Name        string
	Version     string
	Description *string
	Status      Status
	Metadata    types.JSONB[map[string]string]
	Tags        types.JSONB[map[string]string]
	CreatedAt   time.Time
	CreatedBy   string
	ModifiedAt  time.Time
	ModifiedBy  string

	// Vault specific
	Key        string // logical name / path (also SSM parameter name for aws_ssm)
	Store      Store
	Value      string // base64 ciphertext (DB for ds_vault; empty for aws_ssm)
	ACL        types.JSONB[map[string][]string]
	IV         string // base64 nonce
	Tag        string // base64 auth tag
	WrappedDEK string // base64 KMS-encrypted DEK
	KEKKeyID   string // KMS key id/arn (optional but common)
	DEKAlg     string // e.g., AES256-GCM
	KEKAlg     string // e.g., AWS-KMS
}
