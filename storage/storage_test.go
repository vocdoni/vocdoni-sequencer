package storage

import (
	"bytes"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
)

func TestBallotQueue(t *testing.T) {
	c := qt.New(t)
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "db")

	db, err := metadb.New(db.TypePebble, dbPath)
	c.Assert(err, qt.IsNil)

	st := New(db)
	defer st.Close()

	processID := types.ProcessID{
		Address: common.Address{},
		Nonce:   0,
		ChainID: 0,
	}

	// Scenario: No ballots initially
	_, _, err = st.NextBallot()
	c.Assert(err, qt.Equals, ErrNoMoreElements, qt.Commentf("no ballots expected initially"))

	// Create ballots with fixed data for deterministic testing
	ballot1 := &Ballot{
		ProcessID: processID.Marshal(),
		Nullifier: bytes.Repeat([]byte{1}, 32),
		Address:   bytes.Repeat([]byte{1}, 20),
	}
	ballot2 := &Ballot{
		ProcessID: processID.Marshal(),
		Nullifier: bytes.Repeat([]byte{2}, 32),
		Address:   bytes.Repeat([]byte{2}, 20),
	}

	// Push the ballots
	c.Assert(st.PushBallot(ballot1), qt.IsNil)
	c.Assert(st.PushBallot(ballot2), qt.IsNil)

	// Fetch next ballot and verify its content
	b1, b1key, err := st.NextBallot()
	c.Assert(err, qt.IsNil, qt.Commentf("should retrieve a ballot"))
	c.Assert(b1, qt.IsNotNil)
	c.Assert(b1key, qt.IsNotNil)

	// Store the first ballot's nullifier to track which one we got
	firstNullifier := string(b1.Nullifier)

	// Mark the first ballot done, provide a verified ballot
	verified1 := &VerifiedBallot{
		ProcessID:   processID.Marshal(),
		Nullifier:   b1.Nullifier,
		VoterWeight: big.NewInt(42),
	}
	c.Assert(st.MarkBallotDone(b1key, verified1), qt.IsNil)

	// Fetch the second ballot
	b2, b2key, err := st.NextBallot()
	c.Assert(err, qt.IsNil, qt.Commentf("should retrieve second ballot"))
	c.Assert(b2, qt.IsNotNil)
	c.Assert(b2key, qt.IsNotNil)

	// Verify we got a different ballot than the first one
	c.Assert(
		string(b2.Nullifier),
		qt.Not(qt.Equals),
		firstNullifier,
		qt.Commentf("second ballot should be different from first"),
	)

	// Mark second ballot done as well
	verified2 := &VerifiedBallot{
		ProcessID:   processID.Marshal(),
		Nullifier:   b2.Nullifier,
		VoterWeight: big.NewInt(24),
	}
	c.Assert(st.MarkBallotDone(b2key, verified2), qt.IsNil)

	// Now retrieve verified ballots for the process
	// Test GetVerifiedBallots with different maxCount values

	// Test maxCount = 1 should return only one ballot
	vbs1, err := st.GetVerifiedBallots(processID.Marshal(), 1)
	c.Assert(err, qt.IsNil, qt.Commentf("must get verified ballots with maxCount=1"))
	c.Assert(len(vbs1), qt.Equals, 1, qt.Commentf("should return exactly 1 ballot"))

	// Test maxCount = 2 should return both ballots
	vbs2, err := st.GetVerifiedBallots(processID.Marshal(), 2)
	c.Assert(err, qt.IsNil, qt.Commentf("must get verified ballots with maxCount=2"))
	c.Assert(len(vbs2), qt.Equals, 2, qt.Commentf("should return exactly 2 ballots"))

	// Test maxCount = 0 should return no ballots
	vbs0, err := st.GetVerifiedBallots(processID.Marshal(), 0)
	c.Assert(err, qt.IsNil, qt.Commentf("must get verified ballots with maxCount=0"))
	c.Assert(len(vbs0), qt.Equals, 0, qt.Commentf("should return no ballots"))

	// Test maxCount > number of available ballots should return all ballots
	vbs10, err := st.GetVerifiedBallots(processID.Marshal(), 10)
	c.Assert(err, qt.IsNil, qt.Commentf("must get verified ballots with maxCount=10"))
	c.Assert(len(vbs10), qt.Equals, 2, qt.Commentf("should return all available ballots"))

	// Try again NextBallot. There should be no more ballots.
	_, _, err = st.NextBallot()
	c.Assert(err, qt.Equals, ErrNoMoreElements, qt.Commentf("no more ballots expected"))

	// Additional scenario: MarkBallotDone on a non-existent/reserved key
	nonExistentKey := []byte("fakekey")
	err = st.MarkBallotDone(nonExistentKey, verified1)
	c.Assert(err, qt.IsNil)

	// Additional scenario: no verified ballots if none processed
	anotherPID := types.ProcessID{
		Address: common.Address{},
		ChainID: 0,
		Nonce:   999,
	}
	vbsEmpty, err := st.GetVerifiedBallots(anotherPID.Marshal(), 10)
	c.Assert(err, qt.Equals, ErrNotFound, qt.Commentf("no verified ballots for a new process"))
	c.Assert(vbsEmpty, qt.IsNil)
}

func TestBallotBatchQueue(t *testing.T) {
	c := qt.New(t)
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "db")

	db, err := metadb.New(db.TypePebble, dbPath)
	c.Assert(err, qt.IsNil)

	st := New(db)
	defer st.Close()

	processID := types.ProcessID{
		Address: common.Address{},
		Nonce:   0,
		ChainID: 0,
	}

	// Test 1: Empty state
	_, _, err = st.NextBallotBatch(processID.Marshal())
	c.Assert(err, qt.Equals, ErrNoMoreElements, qt.Commentf("no batches expected initially"))

	// Test 2: Single batch lifecycle
	batch1 := &AggregatedBallotBatch{
		ProcessID: processID.Marshal(),
		Ballots: []AggregatedBallot{
			{
				Nullifier:  bytes.Repeat([]byte{1}, 32),
				Address:    bytes.Repeat([]byte{1}, 20),
				Commitment: bytes.Repeat([]byte{1}, 32),
			},
		},
	}

	// Push batch and wait a moment to ensure different timestamps
	c.Assert(st.PushBallotBatch(batch1), qt.IsNil)

	// Get batch
	b1, b1key, err := st.NextBallotBatch(processID.Marshal())
	c.Assert(err, qt.IsNil, qt.Commentf("should retrieve the batch"))
	c.Assert(b1, qt.IsNotNil)
	c.Assert(len(b1.Ballots), qt.Equals, 1)
	c.Assert(string(b1.Ballots[0].Nullifier), qt.Equals, string(batch1.Ballots[0].Nullifier))

	// Mark batch done and wait a moment
	c.Assert(st.MarkBallotBatchDone(b1key), qt.IsNil)

	// Test 3: Multiple batches
	batch2 := &AggregatedBallotBatch{
		ProcessID: processID.Marshal(),
		Ballots: []AggregatedBallot{
			{
				Nullifier:  bytes.Repeat([]byte{2}, 32),
				Address:    bytes.Repeat([]byte{2}, 20),
				Commitment: bytes.Repeat([]byte{2}, 32),
			},
		},
	}

	// Push batch2 and wait
	c.Assert(st.PushBallotBatch(batch2), qt.IsNil)

	// Get and verify batch2
	b2, b2key, err := st.NextBallotBatch(processID.Marshal())
	c.Assert(err, qt.IsNil)
	c.Assert(b2, qt.IsNotNil)
	c.Assert(len(b2.Ballots), qt.Equals, 1)
	c.Assert(string(b2.Ballots[0].Nullifier), qt.Equals, string(batch2.Ballots[0].Nullifier))

	// Mark batch2 done and wait
	c.Assert(st.MarkBallotBatchDone(b2key), qt.IsNil)

	c.Assert(st.ListBallotBatch(), qt.IsNil)

	// Push and verify batch3
	batch3 := &AggregatedBallotBatch{
		ProcessID: processID.Marshal(),
		Ballots: []AggregatedBallot{
			{
				Nullifier:  bytes.Repeat([]byte{3}, 32),
				Address:    bytes.Repeat([]byte{3}, 20),
				Commitment: bytes.Repeat([]byte{3}, 32),
			},
		},
	}

	c.Assert(st.PushBallotBatch(batch3), qt.IsNil)

	b3, b3key, err := st.NextBallotBatch(processID.Marshal())
	c.Assert(err, qt.IsNil)
	c.Assert(b3, qt.IsNotNil)
	c.Assert(len(b3.Ballots), qt.Equals, 1)
	c.Assert(string(b3.Ballots[0].Nullifier), qt.Equals, string(batch3.Ballots[0].Nullifier))

	// Mark batch3 done
	c.Assert(st.MarkBallotBatchDone(b3key), qt.IsNil)

	// Verify no more batches
	_, _, err = st.NextBallotBatch(processID.Marshal())
	c.Assert(err, qt.Equals, ErrNoMoreElements)

	// Test 4: Different process ID
	anotherPID := types.ProcessID{
		Address: common.Address{},
		ChainID: 0,
		Nonce:   999,
	}
	_, _, err = st.NextBallotBatch(anotherPID.Marshal())
	c.Assert(err, qt.Equals, ErrNoMoreElements)
}
