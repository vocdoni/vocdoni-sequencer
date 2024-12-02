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
	"sync"

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
	db db.Database
	// queue in-memory buckets
	votes    map[string]*Vote
	votesMtx sync.RWMutex
	// queue channels
	VotesCh chan *Vote
}

// New creates a new Storage instance.
func New(db db.Database) *Storage {
	return &Storage{db: db}
}

// Close closes the storage.
func (s *Storage) Close() {
	s.db.Close()
}

// setArtifact helper function stores any kind of artifact in the storage. It
// receives the prefix of the key, the key itself and the artifact to store. If
// the key is not provided, it generates it by hashing the artifact itself. It
// returns the final key of the artifact and an error if there is any.
func (s *Storage) setArtifact(prefix []byte, skey string, artifact any) (string, error) {
	// encode the artifact
	data, err := json.Marshal(artifact)
	if err != nil {
		return "", err
	}
	var key []byte
	// if the string key is provided, decode it
	if skey != "" {
		key, err = hex.DecodeString(string(skey))
		if err != nil {
			return "", err
		}
	}
	// if no key is provided, generate it hashing the data
	noKey := len(key) == 0
	if noKey {
		hash := sha256.Sum256(data)
		key = hash[:maxKeySize]
	}
	// instance a write transaction with the prefix provided
	wTx := prefixeddb.NewPrefixedWriteTx(s.db.WriteTx(), prefix)
	// store the artifact in the database with the key generated
	if err := wTx.Set(key, data); err != nil {
		return "", err
	}
	// commit the transaction
	if err := wTx.Commit(); err != nil {
		return "", err
	}
	// if no key was provided, return the key generated
	if noKey {
		return hex.EncodeToString(key), nil
	}
	// otherwise, return the key provided
	return skey, nil
}

func (s *Storage) getArtifact(prefix []byte, key string, artifact any) error {
	rTx := prefixeddb.NewPrefixedReader(s.db, prefix)
	bkey, err := hex.DecodeString(key)
	if err != nil {
		return err
	}
	data, err := rTx.Get(bkey)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, artifact); err != nil {
		return err
	}
	return nil
}

// GetMetadata retrieves the metadata from the storage. It returns an error if
// the metadata is not found or if there is an error while retrieving it. If
// the metadata is found, it returns the metadata unmarshalled.
func (s *Storage) GetMetadata(key string) (*Metadata, error) {
	metadata := &Metadata{}
	if err := s.getArtifact(metadataPrefix, key, metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

// SetMetadata stores the metadata in the storage. It returns the generated key
// of the metadata and an error if there is any.
func (s *Storage) SetMetadata(metadata *Metadata) (string, error) {
	return s.setArtifact(metadataPrefix, "", metadata)
}

func (s *Storage) PushVote(v *Vote) error {
	if _, err := s.setArtifact(votePrefix, v.Nullifier, v); err != nil {
		return err
	}
	s.votesMtx.Lock()
	s.votes[v.Nullifier] = v
	s.votesMtx.Unlock()

	s.VotesCh <- v
	return nil
}
