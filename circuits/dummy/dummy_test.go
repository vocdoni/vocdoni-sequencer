package dummy

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
)

func TestSameCircuitsInfo(t *testing.T) {
	c := qt.New(t)
	// generate inner circuit placeholders
	circomPlaceholder, err := circuits.Circom2GnarkPlaceholder(ballottest.TestCircomVerificationKey)
	c.Assert(err, qt.IsNil)
	// compile the main circuit
	mainCCS, err := frontend.Compile(circuits.VoteVerifierCurve.ScalarField(), r1cs.NewBuilder, &voteverifier.VerifyVoteCircuit{
		CircomProof: circuits.InnerProofBN254{
			VK:    circomPlaceholder.Vk,
			Proof: circomPlaceholder.Proof,
		},
	})
	c.Assert(err, qt.IsNil)
	mainVk := stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](mainCCS)

	dummyCCS, err := frontend.Compile(circuits.VoteVerifierCurve.ScalarField(), r1cs.NewBuilder, Placeholder(mainCCS))
	c.Assert(err, qt.IsNil)
	dummyVk := stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](dummyCCS)

	c.Log("len(G1.K)", len(mainVk.G1.K))
	c.Log("len(CommitmentKeys)", len(mainVk.CommitmentKeys))
	c.Log("PublicAndCommitmentCommitted", mainVk.PublicAndCommitmentCommitted)

	c.Assert(dummyVk.G1.K, qt.HasLen, len(mainVk.G1.K),
		qt.Commentf("G1.K %d vs %d", len(dummyVk.G1.K), len(mainVk.G1.K)))
	c.Assert(dummyVk.CommitmentKeys, qt.HasLen, len(mainVk.CommitmentKeys),
		qt.Commentf("CommitmentKeys %d vs %d", len(dummyVk.CommitmentKeys), len(mainVk.CommitmentKeys)))
	c.Assert(dummyVk.PublicAndCommitmentCommitted, qt.ContentEquals, mainVk.PublicAndCommitmentCommitted,
		qt.Commentf("PublicAndCommitmentCommitted %v vs %v", dummyVk.PublicAndCommitmentCommitted, mainVk.PublicAndCommitmentCommitted))
}
