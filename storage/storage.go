// storage package contains all the artifacts that are stored in the database,
// but also is an abstraction of a queue for the processing of them by different
// services. The storage package includes a prefixed key-value store that allows
// to store the different types of artifacts in the database. The following
// prefixes are used:
//   - 'm/' for metadata
//   - 'c/' for censuses
//   - 'p/' for processes
//   - 'v/' for votes (with their proofs) (queued)
//   - 'au/' for authentications proofs (queued)
//   - 'ag/' for aggregations proofs (queued)
//
// Note: Not all the prefixes support queue operations, only the ones that are
// used in the processing of the artifacts.
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"go.vocdoni.io/dvote/db"
)

const maxKeySize = 12

// Storage is the interface that wraps the basic methods to interact with the
// storage.
type Storage struct {
	db    db.Database
	votes []*Vote
}

// New creates a new Storage instance.
func New(db db.Database) *Storage {
	return &Storage{db: db}
}

func (s *Storage) GetMetadata(key string) (*Metadata, error) {
	data, err := s.db.Get(metadataKey(key))
	if err != nil {
		return nil, err
	}
	metadata := &Metadata{}
	if err := json.Unmarshal(data, metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

func (s *Storage) SetMetadata(metadata *Metadata) (string, error) {
	data, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	key := hex.EncodeToString(hash[:maxKeySize])
	wTx := s.db.WriteTx()
	if err := wTx.Set(metadataKey(key), data); err != nil {
		return "", err
	}
	if err := wTx.Commit(); err != nil {
		return "", err
	}
	return key, nil
}
