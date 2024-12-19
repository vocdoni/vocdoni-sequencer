package storage

import (
	"errors"
	"fmt"

	"go.vocdoni.io/dvote/db/prefixeddb"
)

// PushBallot stores a new ballot into the pending ballots queue.
func (s *Storage) PushBallot(b *Ballot) error {
	val, err := encodeArtifact(b)
	if err != nil {
		return fmt.Errorf("encode ballot: %w", err)
	}
	wTx := prefixeddb.NewPrefixedWriteTx(s.db.WriteTx(), ballotPrefix)
	key := hashKey(val)
	if err := wTx.Set(key, val); err != nil {
		wTx.Discard()
		return err
	}
	return wTx.Commit()
}

// NextBallot returns the next non-reserved ballot, creates a reservation, and returns it.
func (s *Storage) NextBallot() (*Ballot, []byte, error) {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()

	pr := prefixeddb.NewPrefixedReader(s.db, ballotPrefix)
	var chosenKey, chosenVal []byte
	pr.Iterate(nil, func(k, v []byte) bool {
		// check if reserved
		if s.isReserved(ballotReservationPrefix, k) {
			return true
		}
		chosenKey = k
		chosenVal = v
		return false
	})
	if chosenVal == nil {
		return nil, nil, ErrNoMoreElements
	}

	var b Ballot
	if err := decodeArtifact(chosenVal, &b); err != nil {
		return nil, nil, fmt.Errorf("decode ballot: %w", err)
	}

	// set reservation
	if err := s.setReservation(ballotReservationPrefix, chosenKey); err != nil {
		// can't reserve? try next would be ideal, but let's return no elements
		return nil, nil, ErrNoMoreElements
	}

	return &b, chosenKey, nil
}

// MarkBallotDone called after we have processed the ballot. We must remove reservation and possibly move it to next stage.
// In this scenario, next stage is verifiedBallot so we do not store the original ballot.
// The aggregator stage expects verified ballots as input.
func (s *Storage) MarkBallotDone(k []byte, vb *VerifiedBallot) error {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()

	// remove reservation
	if err := s.deleteArtifact(ballotReservationPrefix, k); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("delete reservation: %w", err)
	}

	// remove from pending queue
	if err := s.deleteArtifact(ballotPrefix, k); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("delete pending ballot: %w", err)
	}

	// store verified ballot
	val, err := encodeArtifact(vb)
	if err != nil {
		return fmt.Errorf("encode verified ballot: %w", err)
	}
	wTx := prefixeddb.NewPrefixedWriteTx(s.db.WriteTx(), verifiedBallotPrefix)
	// key with processID as prefix + unique portion from original key
	combKey := append(vb.ProcessID, k...)
	if err := wTx.Set(combKey, val); err != nil {
		wTx.Discard()
		return err
	}
	return wTx.Commit()
}

// GetVerifiedBallots returns all verified ballots for a given processID
func (s *Storage) GetVerifiedBallots(processID []byte) ([]VerifiedBallot, error) {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()

	rd := prefixeddb.NewPrefixedReader(s.db, verifiedBallotPrefix)
	var res []VerifiedBallot
	rd.Iterate(processID, func(k, v []byte) bool {
		var vb VerifiedBallot
		if err := decodeArtifact(v, &vb); err == nil {
			res = append(res, vb)
		}
		return true
	})
	if len(res) == 0 {
		return nil, ErrNotFound
	}
	return res, nil
}

// PushBallotBatch pushes an aggregated ballot batch to the aggregator queue.
func (s *Storage) PushBallotBatch(abb *AggregatedBallotBatch) error {
	val, err := encodeArtifact(abb)
	if err != nil {
		return fmt.Errorf("encode batch: %w", err)
	}
	wTx := prefixeddb.NewPrefixedWriteTx(s.db.WriteTx(), aggregBatchPrefix)
	key := hashKey(val)
	if err := wTx.Set(append(abb.ProcessID, key...), val); err != nil {
		wTx.Discard()
		return err
	}
	return wTx.Commit()
}

// ListBallotBatch returns all aggregated ballot batches keys.
func (s *Storage) ListBallotBatch() [][]byte {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()

	rd := prefixeddb.NewPrefixedReader(s.db, aggregBatchPrefix)
	var res [][]byte
	rd.Iterate(nil, func(k, v []byte) bool {
		k2 := make([]byte, len(k))
		copy(k2, k)
		res = append(res, k2)
		return true
	})
	return res
}

// NextBallotBatch returns the next aggregated ballot batch for a given processID, sets a reservation.
func (s *Storage) NextBallotBatch(processID []byte) (*AggregatedBallotBatch, []byte, error) {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()

	pr := prefixeddb.NewPrefixedReader(s.db, aggregBatchPrefix)
	var chosenKey, chosenVal []byte
	pr.Iterate(processID, func(k, v []byte) bool {
		if s.isReserved(aggregBatchReservPrefix, k) {
			return true
		}
		chosenKey = append(processID, k...)
		chosenVal = v
		return false
	})
	if chosenVal == nil {
		return nil, nil, ErrNoMoreElements
	}

	var abb AggregatedBallotBatch
	if err := decodeArtifact(chosenVal, &abb); err != nil {
		return nil, nil, fmt.Errorf("decode agg batch: %w", err)
	}

	if err := s.setReservation(aggregBatchReservPrefix, chosenKey); err != nil {
		return nil, nil, ErrNoMoreElements
	}

	return &abb, chosenKey, nil
}

// MarkBallotBatchDone called after processing aggregator batch. For simplicity, we just remove it from aggregator queue and reservation.
func (s *Storage) MarkBallotBatchDone(k []byte) error {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()
	if err := s.deleteArtifact(aggregBatchReservPrefix, k); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := s.deleteArtifact(aggregBatchPrefix, k); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}
