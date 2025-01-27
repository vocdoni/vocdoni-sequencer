package state

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/prefixeddb"
)

var (
	// HashFunc is the hash function used in the state tree.
	HashFunc = arbo.HashFunctionMiMC_BN254
	// Curve is the curve used for the encryption
	Curve = curves.New(curves.CurveTypeBabyJubJubGnark)
)

var (
	KeyProcessID     = []byte{0x00}
	KeyCensusRoot    = []byte{0x01}
	KeyBallotMode    = []byte{0x02}
	KeyEncryptionKey = []byte{0x03}
	KeyResultsAdd    = []byte{0x04}
	KeyResultsSub    = []byte{0x05}
)

// State represents a state tree
type State struct {
	tree      *arbo.Tree
	processID []byte
	db        db.Database
	dbTx      db.WriteTx

	// TODO: unexport these, add ArboProofs and only export those via a method
	ResultsAdd     *elgamal.Ballot
	ResultsSub     *elgamal.Ballot
	BallotSum      *elgamal.Ballot
	OverwriteSum   *elgamal.Ballot
	ballotCount    int
	overwriteCount int
	votes          []*Vote
}

// New creates or opens a State stored in the passed database.
// The processId is used as a prefix for the keys in the database.
func New(db db.Database, processId []byte) (*State, error) {
	pdb := prefixeddb.NewPrefixedDatabase(db, processId)
	tree, err := arbo.NewTree(arbo.Config{
		Database: pdb, MaxLevels: circuits.StateProofMaxLevels,
		HashFunction: HashFunc,
	})
	if err != nil {
		return nil, err
	}

	return &State{
		db:        pdb,
		tree:      tree,
		processID: processId,
	}, nil
}

// Initialize creates a new State, initialized with the passed parameters.
//
// after Initialize, caller is expected to StartBatch, AddVote, EndBatch, StartBatch...
func (o *State) Initialize(censusRoot, ballotMode, encryptionKey []byte) error {
	if err := o.tree.Add(KeyProcessID, o.processID); err != nil {
		return err
	}
	if err := o.tree.Add(KeyCensusRoot, censusRoot); err != nil {
		return err
	}
	if err := o.tree.Add(KeyBallotMode, ballotMode); err != nil {
		return err
	}
	if err := o.tree.Add(KeyEncryptionKey, encryptionKey); err != nil {
		return err
	}
	if err := o.tree.Add(KeyResultsAdd, elgamal.NewBallot(Curve).Serialize()); err != nil {
		return err
	}
	if err := o.tree.Add(KeyResultsSub, elgamal.NewBallot(Curve).Serialize()); err != nil {
		return err
	}
	return nil
}

// Close the database, no more operations can be done after this.
func (o *State) Close() error {
	return o.db.Close()
}

// StartBatch resets counters and sums to zero,
// and creates a new write transaction in the db
func (o *State) StartBatch() error {
	o.dbTx = o.db.WriteTx()
	if o.ResultsAdd == nil {
		o.ResultsAdd = elgamal.NewBallot(Curve)
	}
	if o.ResultsSub == nil {
		o.ResultsSub = elgamal.NewBallot(Curve)
	}

	{
		_, v, err := o.tree.Get(KeyResultsAdd)
		if err != nil {
			return err
		}
		if err := o.ResultsAdd.Deserialize(v); err != nil {
			return fmt.Errorf("ResultsAdd: %w", err)
		}
	}
	{
		_, v, err := o.tree.Get(KeyResultsSub)
		if err != nil {
			return err
		}
		if err := o.ResultsSub.Deserialize(v); err != nil {
			return fmt.Errorf("ResultsSub: %w", err)
		}
	}

	o.BallotSum = elgamal.NewBallot(Curve)
	o.OverwriteSum = elgamal.NewBallot(Curve)
	o.ballotCount = 0
	o.overwriteCount = 0
	o.votes = []*Vote{}
	return nil
}

func (o *State) EndBatch() error {
	return o.dbTx.Commit()
}

func (o *State) Root() ([]byte, error) {
	return o.tree.Root()
}

func (o *State) RootAsBigInt() (*big.Int, error) {
	root, err := o.tree.Root()
	if err != nil {
		return nil, err
	}
	return arbo.BytesToBigInt(root), nil
}

func (o *State) BallotCount() int {
	return o.ballotCount
}

func (o *State) OverwriteCount() int {
	return o.overwriteCount
}

func (o *State) Votes() []*Vote {
	return o.votes
}

func (o *State) PaddedVotes() []*Vote {
	v := slices.Clone(o.votes)
	for len(v) < circuits.VotesPerBatch {
		v = append(v, &Vote{
			Nullifier:  []byte{0x00},
			Ballot:     elgamal.NewBallot(Curve),
			Address:    []byte{0x00},
			Commitment: big.NewInt(0),
		})
	}
	return v
}

func (o *State) ProcessID() []byte {
	_, v, err := o.tree.Get(KeyProcessID)
	if err != nil {
		panic(err)
	}
	return v
}

func (o *State) CensusRoot() []byte {
	_, v, err := o.tree.Get(KeyCensusRoot)
	if err != nil {
		panic(err)
	}
	return v
}

func (o *State) BallotMode() []byte {
	_, v, err := o.tree.Get(KeyBallotMode)
	if err != nil {
		panic(err)
	}
	return v
}

func (o *State) EncryptionKey() []byte {
	_, v, err := o.tree.Get(KeyEncryptionKey)
	if err != nil {
		panic(err)
	}
	return v
}

func (o *State) AggregatedWitnessInputs() [][]byte {
	// all of the following values compose the preimage that is hashed
	// to produce the public input needed to verify AggregatedProof.
	// ProcessID
	// CensusRoot
	// BallotMode
	// EncryptionKey
	// Nullifiers
	// Ballots
	// Addressess
	// Commitments

	inputs := [][]byte{
		o.ProcessID(),
		o.CensusRoot(),
		o.BallotMode(),
		o.EncryptionKey(),
	}
	votes := o.PaddedVotes()
	for _, v := range votes {
		inputs = append(inputs, v.Nullifier)
	}
	for _, v := range votes {
		inputs = append(inputs, v.Ballot.Serialize())
	}
	for _, v := range votes {
		inputs = append(inputs, v.Address)
	}
	for _, v := range votes {
		inputs = append(inputs, arbo.BigIntToBytes(HashFunc.Len(), v.Commitment))
	}
	return inputs
}

func (o *State) AggregatedWitnessHash() ([]byte, error) {
	hash, err := HashFunc.Hash(o.AggregatedWitnessInputs()...)
	if err != nil {
		return nil, err
	}
	return hash, nil
}
