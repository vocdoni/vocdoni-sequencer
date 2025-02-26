package aggregatortest

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	voteverifiertest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/voteverifier"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
)

// AggregatorTestResults struct includes relevant data after AggregatorCircuit
// inputs generation
type AggregatorTestResults struct {
	Process circuits.Process[*big.Int]
	Votes   []state.Vote
}

/*
TODO: Fix and refactor this function

func LocalInputsForTest(nValidVoters int) (AggregatorTestResults, aggregator.AggregatorCircuit, aggregator.AggregatorCircuit, error) {
	// dummy vkey
	dummyVkFd, err := os.Open("dummy.vkey")
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	dummyVk := groth16.NewVerifyingKey(gecc.BLS12_377)
	if _, err := dummyVk.ReadFrom(dummyVkFd); err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	recursiveDummyVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](dummyVk)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// dummy proof
	dummyProofFd, err := os.Open("dummy.proof")
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	dummyProof := groth16.NewProof(gecc.BLS12_377)
	if _, err := dummyProof.ReadFrom(dummyProofFd); err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	recursiveDummyProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyProof)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// base vkey
	baseVkFd, err := os.Open("vote_verifier.vkey")
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	baseVk := groth16.NewVerifyingKey(gecc.BLS12_377)
	if _, err := baseVk.ReadFrom(baseVkFd); err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	recursiveBaseVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](baseVk)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// proofs and witnesses
	proofs := [aggregator.MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	for i := 0; i < aggregator.MaxVotes; i++ {
		if i < nValidVoters {
			proofFd, err := os.Open(fmt.Sprintf("vote_verifier_%d.proof", i))
			if err != nil {
				return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
			}
			proof := groth16.NewProof(gecc.BLS12_377)
			if _, err := proof.ReadFrom(proofFd); err != nil {
				return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
			}
			recursiveProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
			if err != nil {
				return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
			}
			proofs[i] = recursiveProof
		} else {
			proofs[i] = recursiveDummyProof
		}
	}
	// inputs
	resultsFd, err := os.Open("aggregator_test_inputs.json")
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	results := AggregatorTestResults{}
	if err := json.NewDecoder(resultsFd).Decode(&results); err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// load constrain system
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &voteverifier.VerifyVoteCircuit{})
	if err != nil {
		log.Println("error compiling constraint system", err)
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	builder, err := r1cs.NewBuilder(ecc.BLS12_377.ScalarField(), frontend.CompileConfig{
		CompressThreshold: 300,
	})
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	ccs, err := builder.Compile()
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	if _, err := ccs.ReadFrom(fdCCS); err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	recursiveSlots := [aggregator.MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	for i := 0; i < aggregator.MaxVotes; i++ {
		recursiveSlots[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](ccs)
	}
	placeholder := aggregator.AggregatorCircuit{
		BaseVerificationKey:  recursiveBaseVk,
		DummyVerificationKey: recursiveDummyVk,
		Proofs:               recursiveSlots,
	}
	assignments := aggregator.AggregatorCircuit{
		InputsHash: emulated.ValueOf[sw_bn254.ScalarField](results.InputsHash),
		ValidVotes: aggregator.EncodeProofsSelector(nValidVoters),
		BallotMode: circuits.BallotMode[emulated.Element[sw_bn254.ScalarField]]{
			MaxCount:        emulated.ValueOf[sw_bn254.ScalarField](ballottest.MaxCount),
			ForceUniqueness: emulated.ValueOf[sw_bn254.ScalarField](ballottest.ForceUniqueness),
			MaxValue:        emulated.ValueOf[sw_bn254.ScalarField](ballottest.MaxValue),
			MinValue:        emulated.ValueOf[sw_bn254.ScalarField](ballottest.MinValue),
			MaxTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](int(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * ballottest.MaxCount),
			MinTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](ballottest.MaxCount),
			CostExp:         emulated.ValueOf[sw_bn254.ScalarField](ballottest.CostExp),
			CostFromWeight:  emulated.ValueOf[sw_bn254.ScalarField](ballottest.CostFromWeight),
		},
		EncryptionPubKey: [2]emulated.Element[sw_bn254.ScalarField]{
			emulated.ValueOf[sw_bn254.ScalarField](results.EncryptionPubKey[0]),
			emulated.ValueOf[sw_bn254.ScalarField](results.EncryptionPubKey[1]),
		},
		ProcessId:  emulated.ValueOf[sw_bn254.ScalarField](results.ProcessId),
		CensusRoot: emulated.ValueOf[sw_bn254.ScalarField](results.CensusRoot),
		Proofs:     proofs,
	}
	return results, placeholder, assignments, nil
}
*/

// AggregatorInputsForTest returns the AggregatorTestResults, the placeholder
// and the assignments of a AggregatorCircuit for the processId provided
// generating nValidVotes. If something fails it returns an error.
func AggregatorInputsForTest(processId []byte, nValidVotes int, persist bool) (
	*AggregatorTestResults, *aggregator.AggregatorCircuit, *aggregator.AggregatorCircuit, error,
) {
	// generate users accounts and census
	vvData := []voteverifiertest.VoterTestData{}
	for range nValidVotes {
		privKey, pubKey, address, err := ballottest.GenECDSAaccountForTest()
		if err != nil {
			return nil, nil, nil, err
		}
		vvData = append(vvData, voteverifiertest.VoterTestData{
			PrivKey: privKey,
			PubKey:  pubKey,
			Address: address,
		})
	}
	// generate vote verifier circuit and inputs
	vvInputs, vvPlaceholder, vvAssigments, err := voteverifiertest.VoteVerifierInputsForTest(vvData, processId)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("voteverifier inputs: %w", err)
	}
	// compile vote verifier circuit
	vvCCS, err := frontend.Compile(circuits.VoteVerifierCurve.ScalarField(), r1cs.NewBuilder, &vvPlaceholder)
	if err != nil {
		return nil, nil, nil, err
	}
	vvPk, vvVk, err := groth16.Setup(vvCCS)
	if err != nil {
		return nil, nil, nil, err
	}
	/*
		TODO: uncomment this block when the LocalInputsForTest function is fixed
		if persist {
			if err := circuits.StoreConstraintSystem(vvCCS, "vote_verifier"); err != nil {
				log.Println("error persisting constraint system", err)
			}
			if err := circuits.StoreVerificationKey(vvVk, "vote_verifier"); err != nil {
				log.Println("error persisting verification key", err)
			}
		}
	*/
	// generate voters proofs
	proofs := [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	witnesses := [circuits.VotesPerBatch]stdgroth16.Witness[sw_bls12377.ScalarField]{}
	for i := range vvAssigments {
		// parse the witness to the circuit
		fullWitness, err := frontend.NewWitness(&vvAssigments[i], circuits.VoteVerifierCurve.ScalarField())
		if err != nil {
			return nil, nil, nil, err
		}
		// generate the proof
		proof, err := groth16.Prove(vvCCS, vvPk, fullWitness, stdgroth16.GetNativeProverOptions(
			circuits.AggregatorCurve.ScalarField(),
			circuits.VoteVerifierCurve.ScalarField()))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("err proving voteverifier circuit %d: %w", i, err)
		}
		// convert the proof to the circuit proof type
		proofs[i], err = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
		if err != nil {
			return nil, nil, nil, err
		}
		// convert the public inputs to the circuit public inputs type
		publicWitness, err := fullWitness.Public()
		if err != nil {
			return nil, nil, nil, err
		}
		witnesses[i], err = stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](publicWitness)
		if err != nil {
			return nil, nil, nil, err
		}
		/*
			TODO: uncomment this block when the LocalInputsForTest function is fixed
			if persist {
				if err := circuits.StoreProof(proof, fmt.Sprintf("vote_verifier_%d", i)); err != nil {
					log.Println("error persisting proof and witness", err)
				}
				if err := circuits.StoreWitness(fullWitness, fmt.Sprintf("vote_verifier_%d", i)); err != nil {
					log.Println("error persisting proof and witness", err)
				}
			}
		*/
	}
	// init final assignments stuff
	finalAssigments := &aggregator.AggregatorCircuit{
		ValidProofs: nValidVotes,
		Proofs:      proofs,
		Witnesses:   witnesses,
	}
	// fill assignments with dummy values
	if err := finalAssigments.FillWithDummy(vvCCS, vvPk, ballottest.TestCircomVerificationKey, nValidVotes); err != nil {
		return nil, nil, nil, err
	}
	// fix the vote verifier verification key
	fixedVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vvVk)
	if err != nil {
		return nil, nil, nil, err
	}
	// create final placeholder
	finalPlaceholder := &aggregator.AggregatorCircuit{
		Proofs:          [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{},
		Witnesses:       [circuits.VotesPerBatch]stdgroth16.Witness[sw_bls12377.ScalarField]{},
		VerificationKey: fixedVk,
	}
	for i := range circuits.VotesPerBatch {
		finalPlaceholder.Proofs[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](vvCCS)
		finalPlaceholder.Witnesses[i] = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](vvCCS)
	}
	// TODO: drop this compat-code when previous circuits are also refactored and can do Votes = vvInputs.Votes
	votes := []state.Vote{}
	for i := range nValidVotes {
		votes = append(votes, state.Vote{
			Address:    arbo.BigIntToBytes(32, vvInputs.Addresses[i]),
			Commitment: vvInputs.Commitments[i],
			Nullifier:  arbo.BigIntToBytes(32, vvInputs.Nullifiers[i]),
			Ballot:     &vvInputs.Ballots[i],
		})
	}
	/*
		TODO: uncomment this block when the LocalInputsForTest function is fixed
		if persist {
			// persist the results
			bRes, err := res.MarshalJSON()
			if err != nil {
				log.Println("error marshalling AggregatorTestResults", err)
				return res, finalPlaceholder, finalAssigments, nil
			}
			if err := os.WriteFile("aggregator_test_inputs.json", bRes, 0o644); err != nil {
				log.Println("error writing AggregatorTestResults", err)
			}
		}
	*/
	return &AggregatorTestResults{
		Process: circuits.Process[*big.Int]{
			ID:            vvInputs.ProcessID,
			CensusRoot:    vvInputs.CensusRoot,
			EncryptionKey: vvInputs.EncryptionPubKey,
		},
		Votes: votes,
	}, finalPlaceholder, finalAssigments, nil
}
