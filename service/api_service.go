package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/vocdoni/vocdoni-z-sandbox/api"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
)

// APIService represents a service that manages the HTTP API server.
type APIService struct {
	storage *storage.Storage
	api     *api.API
	mu      sync.Mutex
	cancel  context.CancelFunc
	host    string
	port    int
}

// NewAPIService creates a new APIService instance.
func NewAPI(storage *storage.Storage, host string, port int) *APIService {
	return &APIService{
		storage: storage,
		host:    host,
		port:    port,
	}
}

// Start begins the API server. It returns an error if the service
// is already running or if it fails to start.
func (as *APIService) Start(ctx context.Context) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	if as.cancel != nil {
		return fmt.Errorf("service already running")
	}

	_, as.cancel = context.WithCancel(ctx)

	// Create API instance with existing storage
	var err error
	as.api, err = api.New(&api.APIConfig{
		Host:    as.host,
		Port:    as.port,
		Storage: as.storage,
	})
	if err != nil {
		as.cancel = nil
		return fmt.Errorf("failed to start API server: %w", err)
	}

	return nil
}

// Stop halts the API server.
func (as *APIService) Stop() {
	as.mu.Lock()
	defer as.mu.Unlock()

	if as.cancel != nil {
		as.cancel()
		as.cancel = nil
	}
	as.storage.Close()
}

// HostPort returns the host and port of the API server.
func (as *APIService) HostPort() (string, int) {
	return as.host, as.port
}
