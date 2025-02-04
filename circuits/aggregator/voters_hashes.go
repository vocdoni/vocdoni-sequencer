package aggregator

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/gnark-crypto-primitives/emulated/bn254/twistededwards/mimc7"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
)

// VotersHashes is a struct that contains the hashes of the voters. It is used
// to calculate the sum of the hashes and to generate the witness for the i-th
// voter of a batch of voters.
type VotersHashes struct {
	Hashes [circuits.VotesPerBatch]emulated.Element[sw_bn254.ScalarField]
}

// VoterHashFn function calculates the mimc7 hash of the provided inputs. It
// returns the hash of the inputs.
func VoterHashFn(api frontend.API, inpus ...emulated.Element[sw_bn254.ScalarField]) emulated.Element[sw_bn254.ScalarField] {
	hFn, err := mimc7.NewMiMC(api)
	if err != nil {
		circuits.FrontendError(api, "failed to create emulated MiMC hash function", err)
	}
	if err := hFn.Write(inpus...); err != nil {
		circuits.FrontendError(api, "failed to write inputs to emulated MiMC hash function", err)
	}
	return hFn.Sum()
}

// AssertSumIsEqual method calculates the mimc7 sum of the current hashes and
// asserts that it is equal to the expected provided value.
func (vh VotersHashes) AssertSumIsEqual(api frontend.API, expected emulated.Element[sw_bn254.ScalarField]) {
	// initialize the hash function
	hFn, err := mimc7.NewMiMC(api)
	if err != nil {
		circuits.FrontendError(api, "failed to create emulated MiMC hash function", err)
	}
	// write hashes and assert the sum
	if err := hFn.Write(vh.Hashes[:]...); err != nil {
		circuits.FrontendError(api, "failed to write inputs to emulated MiMC hash function", err)
	}
	hFn.AssertSumIsEqual(expected)
}

// ToWitness method calculates the witness for the i-th voter using the current
// hashes. It receives the index of the desired voter hash and a valid bit as
// frontend.Variable. It takes the hash of the i-th voter and,  after reduce it
// in its field, splits it in 4 elements, each of bls12377 element has as first
// limb each limb of the original bn254 hash. The valid bit is used to select
// the limb of the hash to be used in the final element, between the valid limb
// of the dummy one (1 if it is the first limb, 0 otherwise).
//
//	  validWitness = {
//			Public: [
//				[hashes[i].Limbs[0], 0, 0, 0],
//	  			[hashes[i].Limbs[1], 0, 0, 0],
//				[hashes[i].Limbs[2], 0, 0, 0],
//				[hashes[i].Limbs[3], 0, 0, 0],
//			],
//	  }
//	  dummyWitness = {
//			Public: [
//				[1, 0, 0, 0],
//	  			[0, 0, 0, 0],
//				[0, 0, 0, 0],
//				[0, 0, 0, 0],
//			],
//	  }
func (vh VotersHashes) ToWitness(api frontend.API, idx int, valid frontend.Variable) (
	groth16.Witness[sw_bls12377.ScalarField], error,
) {
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		circuits.FrontendError(api, "failed to create field", err)
	}
	reducedHash := field.Reduce(&vh.Hashes[idx])
	// split the hash in 4 elements, each of bls12377 element has as first
	// limb each limb of the original bn254 hash, including the dummy elements
	dummyLimbs := []frontend.Variable{1, 0, 0, 0}
	splitedHash := []emulated.Element[sw_bls12377.ScalarField]{}
	for i, limb := range reducedHash.Limbs {
		finalLimb := api.Select(valid, limb, dummyLimbs[i])
		// store the new element with the final limb and 0 for the rest
		splitedHash = append(splitedHash, emulated.Element[sw_bls12377.ScalarField]{
			Limbs: []frontend.Variable{finalLimb, 0, 0, 0},
		})
	}
	return groth16.Witness[sw_bls12377.ScalarField]{Public: splitedHash}, nil
}
