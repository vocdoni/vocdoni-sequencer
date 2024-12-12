package storage

import (
	"fmt"

	"github.com/vocdoni/vocdoni-z-sandbox/storage/db"
	"github.com/vocdoni/vocdoni-z-sandbox/storage/db/metadb"
	"github.com/vocdoni/vocdoni-z-sandbox/storage/db/prefixeddb"
)

const (
	// KeyPrefix is the prefix for all keys in the storage
	keyPrefix = "k"
)

var (
	ErrNotFound = fmt.Errorf("key not found in storage")
)

// Storage is a wrapper around a database that stores different types of data.
type Storage struct {
	keys *prefixeddb.PrefixedDatabase
}

// NewStorage creates a new storage instance.
func NewStorage(dataDir string) (*Storage, error) {
	database, err := metadb.New(db.TypePebble, dataDir)
	if err != nil {
		return nil, err
	}
	return &Storage{
		keys: prefixeddb.NewPrefixedDatabase(database, []byte(keyPrefix)),
	}, nil
}
