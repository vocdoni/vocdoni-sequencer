package census

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vocdoni/arbo"
)

// CensusRef is a reference to a census. It holds the Merkle tree.
// All accesses to the underlying tree (and its currentRoot) are protected by treeMu.
type CensusRef struct {
	ID          uuid.UUID
	MaxLevels   int
	HashType    string
	LastUsed    time.Time
	currentRoot []byte
	tree        *arbo.Tree `gob:"-"`
	// treeMu protects all access to the underlying Merkle tree.
	treeMu sync.Mutex `gob:"-"`
	// updateRootRequest is the channel to send asynchronous root update requests.
	updateRootRequest chan *updateRootRequest `gob:"-"`
}

// Tree returns the underlying arbo.Tree pointer.
// (Not concurrency‑safe; use Insert, Root, or GenProof.)
func (cr *CensusRef) Tree() *arbo.Tree {
	return cr.tree
}

// SetTree sets the arbo.Tree pointer.
func (cr *CensusRef) SetTree(tree *arbo.Tree) {
	cr.tree = tree
}

// sendUpdateRoot sends an update request over the channel and waits until processed.
func (cr *CensusRef) sendUpdateRoot(newRoot []byte) error {
	done := make(chan struct{})
	req := &updateRootRequest{
		censusID: cr.ID,
		newRoot:  newRoot,
		done:     done,
	}
	cr.updateRootRequest <- req
	<-done
	return nil
}

// Insert safely inserts a key/value pair into the Merkle tree.
// It holds treeMu during the Add and Root calls.
func (cr *CensusRef) Insert(key, value []byte) error {
	cr.treeMu.Lock()
	err := cr.tree.Add(key, value)
	if err != nil {
		cr.treeMu.Unlock()
		return err
	}
	newRoot, err := cr.tree.Root()
	cr.treeMu.Unlock()
	if err != nil {
		return err
	}
	return cr.sendUpdateRoot(newRoot)
}

// InsertBatch safely inserts a batch of key/value pairs into the Merkle tree.
func (cr *CensusRef) InsertBatch(keys, values [][]byte) ([]arbo.Invalid, error) {
	cr.treeMu.Lock()
	invalid, err := cr.tree.AddBatch(keys, values)
	if err != nil {
		cr.treeMu.Unlock()
		return invalid, err
	}
	newRoot, err := cr.tree.Root()
	cr.treeMu.Unlock()
	if err != nil {
		return invalid, err
	}
	return invalid, cr.sendUpdateRoot(newRoot)
}

// Root safely returns the current Merkle tree root.
func (cr *CensusRef) Root() []byte {
	cr.treeMu.Lock()
	defer cr.treeMu.Unlock()
	root, err := cr.tree.Root()
	if err != nil {
		return nil
	}
	return root
}

// Size safely returns the number of leaves in the Merkle tree.
func (cr *CensusRef) Size() int {
	cr.treeMu.Lock()
	defer cr.treeMu.Unlock()
	size, err := cr.tree.GetNLeafs()
	if err != nil {
		return 0
	}
	return size
}

// GenProof safely generates a Merkle proof for the given leaf key.
// It returns the proof components and an inclusion boolean.
func (cr *CensusRef) GenProof(key []byte) ([]byte, []byte, []byte, bool, error) {
	cr.treeMu.Lock()
	defer cr.treeMu.Unlock()
	return cr.tree.GenProof(key)
}

// VerifyProof verifies a Merkle proof for the given leaf key.
func VerifyProof(key, value, root, siblings []byte) bool {
	valid, err := arbo.CheckProof(defaultHashFunction, key, value, root, siblings)
	if err != nil {
		return false
	}
	return valid
}
