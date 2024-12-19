package storage

import (
	"encoding/json"

	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ethereum"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// Metadata retrieves the metadata from the storage. It returns an error if
// the metadata is not found or if there is an error while retrieving it. If
// the metadata is found, it returns the metadata unmarshalled.
func (s *Storage) Metadata(pid types.ProcessID) (*types.Metadata, error) {
	artifact, err := s.getArtifact(metadataPrefix, pid.Marshal())
	if err != nil {
		return nil, err
	}
	if artifact == nil {
		return nil, ErrNotFound
	}
	metadata, ok := artifact.(*types.Metadata)
	if !ok {
		panic("unexpected artifact type")
	}
	return metadata, nil
}

// SetMetadata stores the metadata in the storage.
func (s *Storage) SetMetadata(pid types.ProcessID, metadata *types.Metadata) error {
	return s.setArtifact(metadataPrefix, pid.Marshal(), metadata)
}

// MetadataHash returns the hash of the metadata.
func MetadataHash(metadata *types.Metadata) []byte {
	data, err := json.Marshal(metadata)
	if err != nil {
		panic(err)
	}
	return ethereum.HashRaw(data)
}
