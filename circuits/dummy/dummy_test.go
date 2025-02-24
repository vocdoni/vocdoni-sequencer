package dummy

import (
	"testing"

	plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
)

func TestSameCircuitsInfoGroth16(t *testing.T) {
	c := qt.New(t)
	// generate inner circuit placeholders
	circomPlaceholder, err := circuits.Circom2GnarkPlaceholder(ballottest.TestCircomVerificationKey)
	c.Assert(err, qt.IsNil)
	// compile the main circuit
	mainCCS, err := frontend.Compile(circuits.VoteVerifierCurve.ScalarField(), r1cs.NewBuilder, &voteverifier.VerifyVoteCircuit{
		CircomProof:           circomPlaceholder.Proof,
		CircomVerificationKey: circomPlaceholder.Vk,
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

func TestSameCircuitsInfoPlonk(t *testing.T) {
	c := qt.New(t)
	// generate inner circuit placeholders
	circomPlaceholder, err := circuits.Circom2GnarkPlaceholder(ballottest.TestCircomVerificationKey)
	c.Assert(err, qt.IsNil)

	// compile the main circuit
	mainCCS, err := frontend.Compile(circuits.VoteVerifierCurve.ScalarField(), scs.NewBuilder, &voteverifier.VerifyVoteCircuit{
		CircomProof:           circomPlaceholder.Proof,
		CircomVerificationKey: circomPlaceholder.Vk,
	})
	c.Assert(err, qt.IsNil)
	srs, srsLagrange, err := unsafekzg.NewSRS(mainCCS)
	c.Assert(err, qt.IsNil)

	_, mainVk, err := plonk.Setup(mainCCS, srs, srsLagrange)
	c.Assert(err, qt.IsNil)
	mainCircuitVk, err := stdplonk.ValueOfCircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine](mainVk)
	c.Assert(err, qt.IsNil)

	dummyCCS, err := frontend.Compile(circuits.VoteVerifierCurve.ScalarField(), scs.NewBuilder, Placeholder(mainCCS))
	c.Assert(err, qt.IsNil)
	_, dummyVk, err := plonk.Setup(dummyCCS, srs, srsLagrange)
	c.Assert(err, qt.IsNil)
	dummyCircuitVk, err := stdplonk.ValueOfCircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine](dummyVk)
	c.Assert(err, qt.IsNil)

	c.Log("CommitmentConstraintIndexes (main vs. dummy)", len(mainCircuitVk.CommitmentConstraintIndexes), len(dummyCircuitVk.CommitmentConstraintIndexes))
	c.Log("Size (main vs. dummy)", mainCircuitVk.Size, dummyCircuitVk.Size)
	c.Log("Qcp (main vs. dummy)", len(mainCircuitVk.Qcp), len(dummyCircuitVk.Qcp))
}
