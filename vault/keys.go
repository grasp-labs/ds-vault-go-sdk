package vault

import (
	"fmt"

	"github.com/google/uuid"
)

// Canonical: /<domain>/<service>/<store>/<secret_id>/<tenant_id>/<environment>
func MakeKey(secretID, tenantID uuid.UUID, store, env string, domain, service string) string {
	if domain == "" {
		domain = "ds"
	}
	if service == "" {
		service = "vault"
	}
	return fmt.Sprintf("/%s/%s/%s/%s/%s/%s", domain, service, store, secretID, tenantID, env)
}
