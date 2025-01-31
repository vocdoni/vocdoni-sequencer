package statetransition

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/tree/smt"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

// MerkleProof stores the leaf, the path, and the root hash.
type MerkleProof struct {
	// Key + Value hashed through Siblings path, should produce Root hash
	Root     frontend.Variable
	Siblings [circuits.StateProofMaxLevels]frontend.Variable
	Key      frontend.Variable
	LeafHash frontend.Variable
	Fnc      frontend.Variable // 0: inclusion, 1: non inclusion
}

// MerkleProofFromArboProof converts an ArboProof into a MerkleProof
func MerkleProofFromArboProof(p *state.ArboProof) MerkleProof {
	leafHash, err := state.HashFunc.Hash(p.Key, p.Value, []byte{1})
	if err != nil {
		panic(err) // TODO: proper error handling
	}
	fnc := 0 // inclusion
	if !p.Existence {
		fnc = 1 // non-inclusion
	}
	return MerkleProof{
		Root:     arbo.BytesToBigInt(p.Root),
		Siblings: padSiblings(p.Siblings),
		Key:      arbo.BytesToBigInt(p.Key),
		LeafHash: arbo.BytesToBigInt(leafHash),
		Fnc:      fnc,
	}
}

// Verify uses smt.Verifier to verify that:
//   - mp.Root matches passed root
//   - mp.LeafHash at position Key belongs to mp.Root
func (mp *MerkleProof) Verify(api frontend.API, hFn utils.Hasher, root frontend.Variable) {
	api.Println("verify proof", mp.String()) // TODO: remove this debug log

	api.AssertIsEqual(root, mp.Root)

	smt.VerifierWithLeafHash(api, hFn,
		1,
		mp.Root,
		mp.Siblings[:],
		mp.Key,
		mp.LeafHash,
		0,
		mp.Key,
		mp.LeafHash,
		0, // inclusion
	)
}

// VerifyLeafHash asserts that smt.Hash1(mp.Key, values...) matches mp.LeafHash
func (mp *MerkleProof) VerifyLeafHash(api frontend.API, hFn utils.Hasher, values ...frontend.Variable) {
	api.AssertIsEqual(mp.LeafHash, smt.Hash1(api, hFn, mp.Key, values...))
}

func (mp *MerkleProof) String() string {
	return fmt.Sprint(mp.Key, "=", util.PrettyHex(mp.LeafHash), " -> ", util.PrettyHex(mp.Root))
}

// MerkleTransition stores a pair of leaves and root hashes, and a single path common to both proofs
type MerkleTransition struct {
	// NewKey + NewValue hashed through Siblings path, should produce NewRoot hash
	NewRoot     frontend.Variable
	Siblings    [circuits.StateProofMaxLevels]frontend.Variable
	NewKey      frontend.Variable
	NewLeafHash frontend.Variable

	// OldKey + OldValue hashed through same Siblings should produce OldRoot hash
	OldRoot     frontend.Variable
	OldKey      frontend.Variable
	OldLeafHash frontend.Variable
	IsOld0      frontend.Variable
	Fnc0        frontend.Variable
	Fnc1        frontend.Variable
}

func MerkleTransitionFromArboTransition(at *state.ArboTransition) (MerkleTransition, error) {
	oldLeafHash, err := state.HashFunc.Hash(at.OldKey, at.OldValue, []byte{1})
	if err != nil {
		return MerkleTransition{}, err
	}
	newLeafHash, err := state.HashFunc.Hash(at.NewKey, at.NewValue, []byte{1})
	if err != nil {
		return MerkleTransition{}, err
	}
	return MerkleTransition{
		NewRoot:     arbo.BytesToBigInt(at.NewRoot),
		Siblings:    padSiblings(at.Siblings),
		NewKey:      arbo.BytesToBigInt(at.NewKey),
		NewLeafHash: arbo.BytesToBigInt(newLeafHash),
		OldRoot:     arbo.BytesToBigInt(at.OldRoot),
		OldKey:      arbo.BytesToBigInt(at.OldKey),
		OldLeafHash: arbo.BytesToBigInt(oldLeafHash),
		IsOld0:      at.IsOld0,
		Fnc0:        at.Fnc0,
		Fnc1:        at.Fnc1,
	}, nil
}

// Verify uses smt.Processor to verify that:
//   - mp.OldRoot matches passed oldRoot
//   - OldKey + OldValue belong to OldRoot
//   - NewKey + NewValue belong to NewRoot
//   - no other changes were introduced between OldRoot -> NewRoot
//
// and returns mp.NewRoot
func (mp *MerkleTransition) Verify(api frontend.API, hFn utils.Hasher, oldRoot frontend.Variable) frontend.Variable {
	api.Println("verify transition", mp.String()) // TODO: remove this debug log

	api.AssertIsEqual(oldRoot, mp.OldRoot)

	root := smt.ProcessorWithLeafHash(api, hFn,
		mp.OldRoot,
		mp.Siblings[:],
		mp.OldKey,
		mp.OldLeafHash,
		mp.IsOld0,
		mp.NewKey,
		mp.NewLeafHash,
		mp.Fnc0,
		mp.Fnc1,
	)

	api.AssertIsEqual(root, mp.NewRoot)
	return mp.NewRoot
}

// VerifyOldLeafHash asserts that smt.Hash1(mp.OldKey, values...) matches mp.OldLeafHash
func (mp *MerkleTransition) VerifyOldLeafHash(api frontend.API, hFn utils.Hasher, values ...frontend.Variable) {
	verifyLeafHash(api, hFn, mp.OldKey, mp.OldLeafHash, mp.IsNoop(api), values...)
}

// VerifyNewLeafHash asserts that smt.Hash1(mp.NewKey, values...) matches mp.NewLeafHash
func (mp *MerkleTransition) VerifyNewLeafHash(api frontend.API, hFn utils.Hasher, values ...frontend.Variable) {
	verifyLeafHash(api, hFn, mp.NewKey, mp.NewLeafHash, mp.IsNoop(api), values...)
}

func verifyLeafHash(api frontend.API, hFn utils.Hasher, key, leafHash, isNoop frontend.Variable, values ...frontend.Variable) {
	api.AssertIsEqual(leafHash,
		api.Select(isNoop, leafHash, // if MerkleTransition is NOOP, skip check
			smt.Hash1(api, hFn, key, values...)))
}

func (mp *MerkleTransition) String() string {
	return fmt.Sprint(util.PrettyHex(mp.OldRoot), " -> ", util.PrettyHex(mp.NewRoot), " | ",
		mp.OldKey, "=", util.PrettyHex(mp.OldLeafHash), " -> ", mp.NewKey, "=", util.PrettyHex(mp.NewLeafHash))
}

// IsUpdate returns true when mp.Fnc0 == 0 && mp.Fnc1 == 1
func (mp *MerkleTransition) IsUpdate(api frontend.API) frontend.Variable {
	fnc0IsZero := api.IsZero(mp.Fnc0)
	fnc1IsOne := api.Sub(1, api.IsZero(mp.Fnc1))
	return api.And(fnc0IsZero, fnc1IsOne)
}

// IsInsert returns true when mp.Fnc0 == 1 && mp.Fnc1 == 0
func (mp *MerkleTransition) IsInsert(api frontend.API) frontend.Variable {
	fnc0IsOne := api.Sub(1, api.IsZero(mp.Fnc0))
	fnc1IsZero := api.IsZero(mp.Fnc1)
	return api.And(fnc1IsZero, fnc0IsOne)
}

// IsInsertOrUpdate returns true when IsInsert or IsUpdate is true
func (mp *MerkleTransition) IsInsertOrUpdate(api frontend.API) frontend.Variable {
	return api.Or(mp.IsInsert(api), mp.IsUpdate(api))
}

// IsNoop returns true when mp.Fnc0 == 0 && mp.Fnc1 == 0
func (mp *MerkleTransition) IsNoop(api frontend.API) frontend.Variable {
	return api.And(api.IsZero(mp.Fnc0), api.IsZero(mp.Fnc1))
}

func padSiblings(unpackedSiblings [][]byte) [circuits.StateProofMaxLevels]frontend.Variable {
	paddedSiblings := [circuits.StateProofMaxLevels]frontend.Variable{}
	for i := range circuits.StateProofMaxLevels {
		if i < len(unpackedSiblings) {
			paddedSiblings[i] = arbo.BytesToBigInt(unpackedSiblings[i])
		} else {
			paddedSiblings[i] = big.NewInt(0)
		}
	}
	return paddedSiblings
}
