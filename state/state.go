package state

import (
	"math/big"

	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
	encrypt "github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
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
	// CurveType is the curve type used for the encryption
	CurveType = curves.CurveTypeBN254
)

// hashFunc is the hash function used in the state tree.
var hashFunc = arbo.HashMiMC_BN254{}

func (o *State) oldVote(nullifier []byte) *encrypt.Ciphertext {
	data, err := o.dbTx.Get(nullifier)
	if err != nil {
		panic(err)
	}
	v := &encrypt.Ciphertext{}
	if err := v.Unmarshal(data); err != nil {
		panic(err)
	}
	return v
}

func (o *State) storeVote(nullifier []byte, vote *encrypt.Ciphertext) {
	data, err := vote.Marshal()
	if err != nil {
		panic(err)
	}
	if err := o.dbTx.Set(nullifier, data); err != nil {
		panic(err)
	}
}

var (
	KeyProcessID     = []byte{0x00}
	KeyCensusRoot    = []byte{0x01}
	KeyBallotMode    = []byte{0x02}
	KeyEncryptionKey = []byte{0x03}
	KeyResultsAdd    = []byte{0x04}
	KeyResultsSub    = []byte{0x05}

	KeyNullifiersOffset = 100 // mock, should really be a prefix, not an offset
	KeyAddressesOffset  = 200 // mock, should really be a prefix, not an offsest
)

// State represents a state tree
type State struct {
	tree      *arbo.Tree
	processID []byte
	db        db.Database
	dbTx      db.WriteTx
	// Witnesses statetransition.Circuit // witnesses for the snark circuit

	resultsAdd     *encrypt.Ciphertext
	resultsSub     *encrypt.Ciphertext
	ballotSum      *encrypt.Ciphertext
	overwriteSum   *encrypt.Ciphertext
	ballotCount    int
	overwriteCount int
	votes          []Vote
}

// New creates or opens a State stored in the passed database.
// The processId is used as a prefix for the keys in the database.
func New(db db.Database, processId []byte) (*State, error) {
	pdb := prefixeddb.NewPrefixedDatabase(db, processId)
	tree, err := arbo.NewTree(arbo.Config{
		Database: pdb, MaxLevels: MaxLevels,
		HashFunction: hashFunc,
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
func (o *State) Initialize(censusRoot, ballotMode, encryptionKey []byte) (*State, error) {
	if err := o.tree.Add(KeyProcessID, o.processID); err != nil {
		return nil, err
	}
	if err := o.tree.Add(KeyCensusRoot, censusRoot); err != nil {
		return nil, err
	}
	if err := o.tree.Add(KeyBallotMode, ballotMode); err != nil {
		return nil, err
	}
	if err := o.tree.Add(KeyEncryptionKey, encryptionKey); err != nil {
		return nil, err
	}
	if err := o.tree.Add(KeyResultsAdd, encrypt.NewCiphertext(CurveType).Serialize()); err != nil {
		return nil, err
	}
	if err := o.tree.Add(KeyResultsSub, encrypt.NewCiphertext(CurveType).Serialize()); err != nil {
		return nil, err
	}
	o.resultsAdd = encrypt.NewCiphertext(CurveType)
	o.resultsSub = encrypt.NewCiphertext(CurveType)
	return o, nil
}

// Close the database, no more operations can be done after this.
func (o *State) Close() error {
	return o.db.Close()
}

func (o *State) RootAsBigInt() (*big.Int, error) {
	root, err := o.tree.Root()
	if err != nil {
		return nil, err
	}
	return arbo.BytesToBigInt(root), nil
}
