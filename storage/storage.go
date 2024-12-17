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
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"sync"

	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/prefixeddb"
)

var (
	// Prefixes for the keys in the database.
	metadataPrefix                 = []byte("m/")
	ballotPrefix                   = []byte("b/")
	ballotProcessingPrefix         = []byte("bp/")
	verifiedBallotPrefix           = []byte("vb/")
	verifiedBallotProcessingPrefix = []byte("vbp/")
	aggrPrefix                     = []byte("ag/")
	aggrProcessingPrefix           = []byte("agp/")
	encryptionKeyPrefix            = []byte("ek/")

	censusPrefix  = []byte("c/")
	processPrefix = []byte("p/")
	votePrefix    = []byte("v/")
	authPrefix    = []byte("au/")

	ErrKeyAlreadyExists = fmt.Errorf("key already exists")
	ErrNotFound         = fmt.Errorf("key not found")
	ErrNoMoreElements   = fmt.Errorf("no more elements")
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
	db         db.Database
	ballotLock sync.Mutex
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
// the key is not provided, it generates it by hashing the artifact itself.
// It returns ErrKeyAlreadyExists if the key already exists.
func (s *Storage) setArtifact(prefix []byte, key []byte, artifact any) error {
	// encode the artifact
	data := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(data).Encode(artifact); err != nil {
		return fmt.Errorf("could not encode: %w", err)
	}
	// if the string key is provided, decode it
	if key == nil {
		hash := sha256.Sum256(data.Bytes())
		key = hash[:maxKeySize]
	}

	// check if key already exists
	if _, err := prefixeddb.NewPrefixedReader(s.db, prefix).Get(key); err == nil {
		return ErrKeyAlreadyExists
	}

	// instance a write transaction with the prefix provided
	wTx := prefixeddb.NewPrefixedWriteTx(s.db.WriteTx(), prefix)
	// store the artifact in the database with the key generated
	if err := wTx.Set(key, data.Bytes()); err != nil {
		return err
	}
	// commit the transaction
	return wTx.Commit()
}

// getArtifact helper function retrieves any kind of artifact from the storage. It
// receives the prefix of the key. It returns the artifact unmarshalled.
// If the key is not provided, it retrieves the first artifact found for the prefix,
// and returns ErrNoMoreElements if there are no more elements.
func (s *Storage) getArtifact(prefix []byte, key []byte) (any, error) {
	var data []byte
	var err error
	if key != nil {
		data, err = prefixeddb.NewPrefixedReader(s.db, prefix).Get(key)
		if err != nil {
			return nil, err
		}
	} else {
		// iterate over the keys in the database, take the next key
		// and get the artifact
		prefixeddb.NewPrefixedReader(s.db, prefix).Iterate(nil, func(_, value []byte) bool {
			data = value
			return false
		})
		if data == nil {
			return nil, ErrNoMoreElements
		}
	}

	var artifact any
	r := bytes.NewReader(data)
	if err := gob.NewDecoder(r).Decode(artifact); err != nil {
		return nil, fmt.Errorf("could not decode artifact: %w", err)
	}

	return artifact, nil
}

func (s *Storage) deleteArtifact(prefix []byte, key []byte) error {
	wTx := prefixeddb.NewPrefixedWriteTx(s.db.WriteTx(), prefix)
	if err := wTx.Delete(key); err != nil {
		return err
	}
	return wTx.Commit()
}

func (s *Storage) getAndDeleteNextArtifact(prefix, innerPrefix []byte) (any, error) {
	var data, key []byte
	// iterate over the keys in the database, take the next key
	// and get the artifact
	prefixeddb.NewPrefixedReader(s.db, prefix).Iterate(innerPrefix, func(k, v []byte) bool {
		data = v
		key = k
		return false
	})
	if data == nil {
		return nil, ErrNoMoreElements
	}
	return data, s.deleteArtifact(prefix, key)
}
