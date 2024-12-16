package storage

import (
	"fmt"

	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/prefixeddb"
)

const (
	// KeyPrefix is the prefix for all keys in the storage
	keyPrefix = "k"
)

var ErrNotFound = fmt.Errorf("key not found in storage")

// Storage is a wrapper around a database that stores different types of data.
type Storage struct {
	keys *prefixeddb.PrefixedDatabase
}

// NewStorage creates a new storage instance.
// It requires a database to store the data. A prefixed database is used internally to avoid key collisions.
func NewStorage(database db.Database) (*Storage, error) {
	return &Storage{
		keys: prefixeddb.NewPrefixedDatabase(database, []byte(keyPrefix)),
	}, nil
}
