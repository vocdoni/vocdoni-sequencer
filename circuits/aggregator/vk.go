package aggregator

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/recursion/groth16"
)

// VerifiyingAndDummyKey struct wraps two Groth16 verification keys and allows
// switching between them in the same circuit to recursively verify a group of
// proofs from two different different circuits recursively.
type VerifiyingAndDummyKey struct {
	Vk    groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:",inherit"`
	Dummy groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:",inherit"`
}

// areSwitchable method checks if both verification keys are equivalent in terms
// of the length of their attributes, such as G1.K components, CommitmentKeys
// and PublicAndCommitmentCommitted. It also checks that the content of the
// PublicAndCommitmentCommitted attributes are the same. It returns an specific
// error if they have different lengths of any of these attributes.
func (v VerifiyingAndDummyKey) areSwitchable() error {
	if len(v.Vk.G1.K) != len(v.Dummy.G1.K) {
		return fmt.Errorf("g1 k len missmatch")
	}
	if len(v.Vk.CommitmentKeys) != len(v.Dummy.CommitmentKeys) {
		return fmt.Errorf("commitmentKeys len missmatch")
	}
	if len(v.Vk.PublicAndCommitmentCommitted) != len(v.Dummy.PublicAndCommitmentCommitted) {
		return fmt.Errorf("public and commitment commited len missmatch")
	}
	for i, vkpc := range v.Vk.PublicAndCommitmentCommitted {
		if len(vkpc) != len(v.Dummy.PublicAndCommitmentCommitted[i]) {
			return fmt.Errorf("public and commitment commited len missmatch")
		}
		for j, ivkpc := range vkpc {
			if ivkpc != v.Dummy.PublicAndCommitmentCommitted[i][j] {
				return fmt.Errorf("public and commitment commited missmatch")
			}
		}
	}
	return nil
}

// Switch method returns the Vk verification key if selection = 1, otherwise
// returns Dummy verification key. It also returns an error if the both
// verification keys are not equivalent.
func (v VerifiyingAndDummyKey) Switch(api frontend.API, selector frontend.Variable) (groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT], error) {
	nilVk := groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}
	// check if both verification keys are equivalent
	if err := v.areSwitchable(); err != nil {
		return nilVk, err
	}
	// select between G1's
	k := []sw_bls12377.G1Affine{}
	for i, vkk := range v.Vk.G1.K {
		k = append(k, *vkk.Select(api, selector, vkk, v.Dummy.G1.K[i]))
	}
	// select between G2's
	gammaNeg := sw_bls12377.G2Affine{
		P: *v.Vk.G2.GammaNeg.P.Select(api, selector, v.Vk.G2.GammaNeg.P, v.Dummy.G2.GammaNeg.P),
	}
	deltaNeg := sw_bls12377.G2Affine{
		P: *v.Vk.G2.DeltaNeg.P.Select(api, selector, v.Vk.G2.DeltaNeg.P, v.Dummy.G2.DeltaNeg.P),
	}
	// select between CommitmentKeys'
	commitmentKeys := []pedersen.VerifyingKey[sw_bls12377.G2Affine]{}
	for i, vkck := range v.Vk.CommitmentKeys {
		commitmentKeys = append(commitmentKeys, pedersen.VerifyingKey[sw_bls12377.G2Affine]{
			G: sw_bls12377.G2Affine{
				P: *vkck.G.P.Select(api, selector, vkck.G.P, v.Dummy.CommitmentKeys[i].G.P),
			},
			GSigmaNeg: sw_bls12377.G2Affine{
				P: *vkck.G.P.Select(api, selector, vkck.GSigmaNeg.P, v.Dummy.CommitmentKeys[i].GSigmaNeg.P),
			},
		})
	}
	// return the built vk selecting between E's
	return groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		E:  *v.Vk.E.Select(api, selector, v.Vk.E, v.Dummy.E),
		G1: struct{ K []sw_bls12377.G1Affine }{k},
		G2: struct {
			GammaNeg sw_bls12377.G2Affine
			DeltaNeg sw_bls12377.G2Affine
		}{
			GammaNeg: gammaNeg,
			DeltaNeg: deltaNeg,
		},
		CommitmentKeys:               commitmentKeys,
		PublicAndCommitmentCommitted: v.Vk.PublicAndCommitmentCommitted,
	}, nil
}
