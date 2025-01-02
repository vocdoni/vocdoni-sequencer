package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/prefixeddb"
)

var (
	ErrKeyAlreadyExists = errors.New("key already exists")
	ErrNotFound         = errors.New("not found")
	ErrNoMoreElements   = errors.New("no more elements")

	// Prefixes
	ballotPrefix               = []byte("b/")
	ballotReservationPrefix    = []byte("br/")
	verifiedBallotPrefix       = []byte("vb/")
	verifiedBallotReservPrefix = []byte("vbr/")
	aggregBatchPrefix          = []byte("ag/")
	aggregBatchReservPrefix    = []byte("agr/")
	encryptionKeyPrefix        = []byte("ek/")
	metadataPrefix             = []byte("m/")

	maxKeySize = 12
)

// reservationRecord stores metadata about a reservation (timestamp, etc.)
type reservationRecord struct {
	Timestamp int64
}

// Storage manages artifacts in various stages with reservations.
type Storage struct {
	db db.Database

	globalLock sync.Mutex
}

// New creates a new Storage instance and attempts to recover from a previous
// crash.
func New(db db.Database) *Storage {
	s := &Storage{db: db}
	go func() {
		if err := s.recover(); err != nil {
			// If we fail here, we may panic because we must ensure consistency.
			panic(fmt.Errorf("failed to recover from crash: %w", err))
		}
	}()
	return s
}

// recover cleans up any stale reservations and ensures that no items are
// blocked. After a crash, any reservations left behind must be cleared so that
// the corresponding ballots or aggregated batches are available for processing
// again.
func (s *Storage) recover() error {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()
	// Clear all reservations
	if err := s.clearAllReservations(ballotReservationPrefix); err != nil {
		return fmt.Errorf("failed to clear ballot reservations: %w", err)
	}
	if err := s.clearAllReservations(verifiedBallotReservPrefix); err != nil {
		return fmt.Errorf("failed to clear verified ballot reservations: %w", err)
	}
	if err := s.clearAllReservations(aggregBatchReservPrefix); err != nil {
		return fmt.Errorf("failed to clear aggregated batch reservations: %w", err)
	}

	return nil
}

// clearAllReservations iterates over the given reservation prefix and removes
// all reservation entries. This ensures that no item remains "reserved" after
// a crash.
func (s *Storage) clearAllReservations(prefix []byte) error {
	rd := prefixeddb.NewPrefixedReader(s.db, prefix)
	var keysToDelete [][]byte
	// Collect all keys to delete
	if err := rd.Iterate(nil, func(k, _ []byte) bool {
		kCopy := make([]byte, len(k))
		copy(kCopy, k)
		keysToDelete = append(keysToDelete, kCopy)
		return true
	}); err != nil {
		return fmt.Errorf("failed to iterate over reservation keys: %w", err)
	}
	// Delete them in a write transaction
	if len(keysToDelete) > 0 {
		wTx := s.db.WriteTx()
		pwt := prefixeddb.NewPrefixedWriteTx(wTx, prefix)
		for _, kk := range keysToDelete {
			if err := pwt.Delete(kk); err != nil {
				pwt.Discard()
				return fmt.Errorf("failed to delete reservation key %x: %w", kk, err)
			}
		}
		if err := pwt.Commit(); err != nil {
			return fmt.Errorf("failed to commit reservation deletion: %w", err)
		}
	}
	return nil
}

func (s *Storage) Close() {
	s.db.Close()
}

// releaseStaleReservations checks and frees stale reservations.
func (s *Storage) ReleaseStaleReservations(maxAge time.Duration) error {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()

	now := time.Now().Unix()

	// Release stale ballot reservations
	if err := s.releaseStaleInPrefix(ballotReservationPrefix, now, maxAge); err != nil {
		return err
	}

	// Release stale verified ballot reservations
	if err := s.releaseStaleInPrefix(verifiedBallotReservPrefix, now, maxAge); err != nil {
		return err
	}

	// Release stale aggregated batch reservations
	if err := s.releaseStaleInPrefix(aggregBatchReservPrefix, now, maxAge); err != nil {
		return err
	}

	return nil
}

func (s *Storage) releaseStaleInPrefix(prefix []byte, now int64, maxAge time.Duration) error {
	rd := prefixeddb.NewPrefixedReader(s.db, prefix)
	var staleKeys [][]byte
	if err := rd.Iterate(nil, func(k, v []byte) bool {
		r, err := decodeReservation(v)
		if err != nil {
			staleKeys = append(staleKeys, append([]byte(nil), k...))
			return true
		}
		if now-r.Timestamp > int64(maxAge.Seconds()) {
			staleKeys = append(staleKeys, append([]byte(nil), k...))
		}
		return true
	}); err != nil {
		return fmt.Errorf("iterate stale reservations: %w", err)
	}
	if len(staleKeys) == 0 {
		return nil
	}

	wTx := s.db.WriteTx()
	for _, sk := range staleKeys {
		pwt := prefixeddb.NewPrefixedWriteTx(wTx, prefix)
		if err := pwt.Delete(sk); err != nil {
			pwt.Discard()
			return fmt.Errorf("delete stale reservation: %w", err)
		}
		if err := pwt.Commit(); err != nil {
			return fmt.Errorf("commit stale deletion: %w", err)
		}
	}
	return nil
}

func (s *Storage) setReservation(prefix, key []byte) error {
	val, err := encodeReservation(&reservationRecord{Timestamp: time.Now().Unix()})
	if err != nil {
		return err
	}
	if _, err := prefixeddb.NewPrefixedReader(s.db, prefix).Get(key); err == nil {
		return ErrKeyAlreadyExists
	}
	wTx := prefixeddb.NewPrefixedWriteTx(s.db.WriteTx(), prefix)
	if err := wTx.Set(key, val); err != nil {
		wTx.Discard()
		return err
	}
	return wTx.Commit()
}

func (s *Storage) isReserved(prefix, key []byte) bool {
	_, err := prefixeddb.NewPrefixedReader(s.db, prefix).Get(key)
	return err == nil
}

func (s *Storage) deleteArtifact(prefix, key []byte) error {
	wTx := prefixeddb.NewPrefixedWriteTx(s.db.WriteTx(), prefix)
	if err := wTx.Delete(key); err != nil {
		wTx.Discard()
		return err
	}
	return wTx.Commit()
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

// getArtifact helper function retrieves any kind of artifact from the storage.
// It receives the prefix of the key. It returns the artifact unmarshalled.
// If the key is not provided, it retrieves the first artifact found for the
// prefix, and returns ErrNoMoreElements if there are no more elements.
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
		if err := prefixeddb.NewPrefixedReader(s.db, prefix).Iterate(nil, func(_, value []byte) bool {
			data = value
			return false
		}); err != nil {
			return nil, err
		}
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
