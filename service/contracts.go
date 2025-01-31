package service

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// ContractsService defines the interface for web3 contract operations
type ContractsService interface {
	MonitorProcessCreation(ctx context.Context, interval time.Duration) (<-chan *types.Process, error)
	CreateProcess(process *types.Process) (*types.ProcessID, *common.Hash, error)
	AccountAddress() common.Address
	WaitTx(hash common.Hash, timeout time.Duration) error
}
