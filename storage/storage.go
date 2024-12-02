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
	"go.vocdoni.io/dvote/db/prefixeddb"
)

var (
	// Prefixes for the keys in the database.
	metadataPrefix = []byte("m/")
	censusPrefix   = []byte("c/")
	processPrefix  = []byte("p/")
	votePrefix     = []byte("v/")
	authPrefix     = []byte("au/")
	aggrPrefix     = []byte("ag/")
)

const (
	// maxKeySize is the maximum size of the key in bytes. It is used to
	// generate the key of the artifacts stored in the database by truncating
	// the hash of the artifact itself.
	maxKeySize = 12
)

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

// Close closes the storage.
func (s *Storage) Close() {
	s.db.Close()
}

// GetMetadata retrieves the metadata from the storage. It returns an error if
// the metadata is not found or if there is an error while retrieving it. If
// the metadata is found, it returns the metadata unmarshalled.
func (s *Storage) GetMetadata(key string) (*Metadata, error) {
	rTx := prefixeddb.NewPrefixedReader(s.db, metadataPrefix)
	bkey, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	data, err := rTx.Get(bkey)
	if err != nil {
		return nil, err
	}
	metadata := &Metadata{}
	if err := json.Unmarshal(data, metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

// SetMetadata stores the metadata in the storage. It returns the key of the
// metadata and an error if there is an error while storing it. The key is
// the first 12 characters of the sha256 hash of the metadata itself.
func (s *Storage) SetMetadata(metadata *Metadata) (string, error) {
	data, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	key := hash[:maxKeySize]
	wTx := prefixeddb.NewPrefixedWriteTx(s.db.WriteTx(), metadataPrefix)
	if err := wTx.Set(key, data); err != nil {
		return "", err
	}
	if err := wTx.Commit(); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
