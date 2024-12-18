package state

import (
	"math/big"

	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/prefixeddb"
)

const (
	// size of the inclusion proofs
	MaxLevels = 160
	// MaxKeyLen is ceil(maxLevels/8)
	MaxKeyLen = (MaxLevels + 7) / 8
	// votes that were processed in AggregatedProof
	VoteBatchSize = 10
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
	ResultsAdd     *elgamal.Ciphertext
	ResultsSub     *elgamal.Ciphertext
	BallotSum      *elgamal.Ciphertext
	OverwriteSum   *elgamal.Ciphertext
	ballotCount    int
	overwriteCount int
	votes          []*Vote
}

// New creates or opens a State stored in the passed database.
// The processId is used as a prefix for the keys in the database.
func New(db db.Database, processId []byte) (*State, error) {
	pdb := prefixeddb.NewPrefixedDatabase(db, processId)
	tree, err := arbo.NewTree(arbo.Config{
		Database: pdb, MaxLevels: MaxLevels,
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
	if err := o.tree.Add(KeyProcessID, o.processID[:31]); err != nil {
		return err
	}
	if err := o.tree.Add(KeyCensusRoot, censusRoot[:31]); err != nil {
		return err
	}
	if err := o.tree.Add(KeyBallotMode, ballotMode[:31]); err != nil {
		return err
	}
	if err := o.tree.Add(KeyEncryptionKey, encryptionKey[:31]); err != nil {
		return err
	}
	if err := o.tree.Add(KeyResultsAdd, elgamal.NewCiphertext(Curve).Serialize()); err != nil {
		return err
	}
	if err := o.tree.Add(KeyResultsSub, elgamal.NewCiphertext(Curve).Serialize()); err != nil {
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
		o.ResultsAdd = elgamal.NewCiphertext(Curve)
	}
	if o.ResultsSub == nil {
		o.ResultsSub = elgamal.NewCiphertext(Curve)
	}

	{
		_, v, err := o.tree.Get(KeyResultsAdd)
		if err != nil {
			return err
		}
		if err := o.ResultsAdd.Deserialize(v); err != nil {
			return err
		}
	}
	{
		_, v, err := o.tree.Get(KeyResultsSub)
		if err != nil {
			return err
		}
		if err := o.ResultsSub.Deserialize(v); err != nil {
			return err
		}
	}

	o.BallotSum = elgamal.NewCiphertext(Curve)
	o.OverwriteSum = elgamal.NewCiphertext(Curve)
	o.ballotCount = 0
	o.overwriteCount = 0
	o.votes = []*Vote{}
	return nil
}

func (o *State) EndBatch() error {
	return o.dbTx.Commit()
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
