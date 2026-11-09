package provider

import (
	"errors"

	"github.com/awapf/terraform-provider-nebula/transitsign"
)

// The transit client lives in the public transitsign package; these aliases
// keep the provider's internal names.
type (
	transitConfig = transitsign.Config
	transitClient = transitsign.Client
	transitKey    = transitsign.Key
)

func newTransitClient(cfg transitConfig) (*transitClient, error) {
	switch {
	case cfg.Address == "":
		return nil, errors.New("no OpenBao/Vault address configured: set the provider's address or BAO_ADDR/VAULT_ADDR")
	case cfg.Token == "":
		return nil, errors.New("no OpenBao/Vault token configured: set the provider's token or BAO_TOKEN/VAULT_TOKEN")
	}
	return transitsign.NewClient(cfg)
}
