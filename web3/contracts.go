package web3

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	bindings "github.com/vocdoni/contracts-z/golang-types"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/web3/rpc"
)

// Addresses contains the addresses of the contracts deployed in the network.
type Addresses struct {
	OrganizationRegistry common.Address
	ProcessRegistry      common.Address
	ResultsRegistry      common.Address
}

// Contracts contains the bindings to the deployed contracts.
type Contracts struct {
	ChainID       uint64
	organizations *bindings.OrganizationRegistry
	processes     *bindings.ProcessRegistry
	web3pool      *rpc.Web3Pool
	cli           *rpc.Client
	privKey       *ecdsa.PrivateKey
	address       common.Address

	knownProcesses map[string]struct{}
	lastWatchBlock uint64
}

// NewContracts creates a new Contracts instance with the given web3 endpoint.
func NewContracts(addresses *Addresses, web3rpc string) (*Contracts, error) {
	w3pool := rpc.NewWeb3Pool()
	chainID, err := w3pool.AddEndpoint(web3rpc)
	if err != nil {
		return nil, fmt.Errorf("failed to add web3 endpoint: %w", err)
	}
	cli, err := w3pool.Client(chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	organizations, err := bindings.NewOrganizationRegistry(addresses.OrganizationRegistry, cli)
	if err != nil {
		return nil, fmt.Errorf("failed to bind organization registry: %w", err)
	}
	process, err := bindings.NewProcessRegistry(addresses.ProcessRegistry, cli)
	if err != nil {
		return nil, fmt.Errorf("failed to bind process registry: %w", err)
	}
	return &Contracts{
		organizations:  organizations,
		processes:      process,
		ChainID:        chainID,
		web3pool:       w3pool,
		cli:            cli,
		knownProcesses: make(map[string]struct{}),
	}, nil
}

// AddWeb3Endpoint adds a new web3 endpoint to the pool.
func (c *Contracts) AddWeb3Endpoint(web3rpc string) error {
	_, err := c.web3pool.AddEndpoint(web3rpc)
	return err
}

// SetAccountPrivateKey sets the private key to be used for signing transactions.
func (c *Contracts) SetAccountPrivateKey(hexPrivKey string) error {
	var err error
	c.privKey, err = crypto.HexToECDSA(hexPrivKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	c.address = crypto.PubkeyToAddress(c.privKey.PublicKey)
	return nil
}

// AccountAddress returns the address of the account used to sign transactions.
func (c *Contracts) AccountAddress() common.Address {
	return c.address
}

// authTransactOpts helper method creates the transact options with the private
// key configured in the CommunityHub. It sets the nonce, gas price, and gas
// limit. If something goes wrong creating the signer, getting the nonce, or
// getting the gas price, it returns an error.
func (c *Contracts) authTransactOpts() (*bind.TransactOpts, error) {
	if c.privKey == nil {
		return nil, fmt.Errorf("no private key set")
	}
	bChainID := new(big.Int).SetUint64(c.ChainID)
	auth, err := bind.NewKeyedTransactorWithChainID(c.privKey, bChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to create transactor: %w", err)
	}
	// create the context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// set the nonce
	log.Debugw("getting nonce", "address", c.address.Hex())
	nonce, err := c.cli.PendingNonceAt(ctx, c.address)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}
	auth.Nonce = new(big.Int).SetUint64(nonce)
	// set the gas tip cap
	if auth.GasTipCap, err = c.cli.SuggestGasTipCap(ctx); err != nil {
		return nil, fmt.Errorf("failed to get gas tip cap: %w", err)
	}
	// set the gas limit
	auth.GasLimit = 10000000
	return auth, nil
}
