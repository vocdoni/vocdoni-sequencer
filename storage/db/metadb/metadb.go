package metadb

import (
	"cmp"
	"fmt"
	"os"
	"testing"

	"github.com/vocdoni/vocdoni-z-sandbox/storage/db"
	"github.com/vocdoni/vocdoni-z-sandbox/storage/db/pebbledb"
)

func New(typ, dir string) (db.Database, error) {
	var database db.Database
	var err error
	opts := db.Options{Path: dir}
	switch typ {
	case db.TypePebble:
		database, err = pebbledb.New(opts)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid dbType: %q. Available types: %q",
			typ, db.TypePebble)
	}
	return database, nil
}

func ForTest() (typ string) {
	return cmp.Or(os.Getenv("DB_TYPE"), "pebble") // default to Pebble
}

func NewTest(tb testing.TB) db.Database {
	database, err := New(ForTest(), tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { database.Close() })
	return database
}
