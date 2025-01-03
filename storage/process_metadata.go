package storage

import (
	"encoding/json"
	"fmt"

	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ethereum"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// ProcessMetadata retrieves the process metadata from the storage.
// It returns nil metadata and ErrNotFound if the metadata is not found.
func (s *Storage) ProcessMetadata(pid types.ProcessID) (*types.Metadata, error) {
	artifact, err := s.getArtifact(metadataPrefix, pid.Marshal())
	if err != nil {
		return nil, err
	}
	metadata, ok := artifact.(*types.Metadata)
	if !ok {
		return nil, fmt.Errorf("unexpected artifact type")
	}
	return metadata, nil
}

// SeProcess stores a process and its metadata into the storage.
func (s *Storage) SetProcess(pid types.ProcessID, metadata *types.Metadata) error {
	return s.setArtifact(metadataPrefix, pid.Marshal(), metadata)
}

// ListProcesses returns the list of process IDs stored in the storage (by SetProcessMetadata) as a list of byte slices.
func (s *Storage) ListProcesses() ([][]byte, error) {
	pids, err := s.listArtifacts(metadataPrefix)
	if err != nil {
		return nil, err
	}
	return pids, nil
}

// MetadataHash returns the hash of the metadata.
func MetadataHash(metadata *types.Metadata) []byte {
	data, err := json.Marshal(metadata)
	if err != nil {
		panic(err)
	}
	return ethereum.HashRaw(data)
}
