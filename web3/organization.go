package web3

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// CreateOrganization creates a new organization in the OrganizationRegistry contract.
func (c *Contracts) CreateOrganization(orgInfo *types.OrganizationInfo) (*common.Hash, error) {
	txOpts, err := c.authTransactOpts()
	if err != nil {
		return nil, fmt.Errorf("failed to create transact options: %w", err)
	}
	tx, err := c.organizations.CreateOrganization(txOpts, c.address, orgInfo.Name, orgInfo.MetadataURI, []common.Address{c.address})
	if err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}
	hash := tx.Hash()
	log.Infow("organization created", "tx", hash.Hex(), "address", c.address.Hex())
	return &hash, nil
}

// Organization returns the organization with the given address from the OrganizationRegistry contract.
func (c *Contracts) Organization(address common.Address) (*types.OrganizationInfo, error) {
	org, err := c.organizations.Organizations(nil, c.address)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	return &types.OrganizationInfo{
		Name:         org.Name,
		MetadataURI:  org.MetadataURI,
		ProcessCount: org.ProcessCount,
	}, nil
}
