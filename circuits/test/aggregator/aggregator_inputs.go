package aggregatortest

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/dummy"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	voteverifiertest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/voteverifier"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
)

// AggregatorTestResults struct includes relevant data after AggregatorCircuit
// inputs generation
type AggregatorTestResults struct {
	InputsHash *big.Int

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
// generating nValidVoters. If something fails it returns an error.
func AggregatorInputsForTest(processId []byte, nValidVoters int, persist bool) (
	AggregatorTestResults, aggregator.AggregatorCircuit, aggregator.AggregatorCircuit, error,
) {
	// generate users accounts and census
	vvData := []voteverifiertest.VoterTestData{}
	for i := 0; i < nValidVoters; i++ {
		privKey, pubKey, address, err := ballottest.GenECDSAaccountForTest()
		if err != nil {
			return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("generate accounts: %w", err)
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
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("voteverifier inputs: %w", err)
	}
	// compile vote verifier circuit
	vvCCS, err := frontend.Compile(circuits.VoteVerifierCurve.ScalarField(), r1cs.NewBuilder, &vvPlaceholder)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("voteverifier compile: %w", err)
	}
	vvPk, vvVk, err := groth16.Setup(vvCCS)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("voteverifier setup: %w", err)
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
	for i := range vvAssigments {
		// parse the witness to the circuit
		fullWitness, err := frontend.NewWitness(&vvAssigments[i], circuits.VoteVerifierCurve.ScalarField())
		if err != nil {
			return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("voteverifier witness: %w", err)
		}
		// generate the proof
		proof, err := groth16.Prove(vvCCS, vvPk, fullWitness, stdgroth16.GetNativeProverOptions(
			circuits.AggregatorCurve.ScalarField(),
			circuits.VoteVerifierCurve.ScalarField()))
		if err != nil {
			return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("err proving voteverifier circuit %d: %w", i, err)
		}
		// convert the proof to the circuit proof type
		proofs[i], err = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
		if err != nil {
			return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("convert voteverifier proof: %w", err)
		}
		// convert the public inputs to the circuit public inputs type
		publicWitness, err := fullWitness.Public()
		if err != nil {
			return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("convert voteverifier public inputs: %w", err)
		}
		err = groth16.Verify(proof, vvVk, publicWitness, stdgroth16.GetNativeVerifierOptions(
			circuits.AggregatorCurve.ScalarField(),
			circuits.VoteVerifierCurve.ScalarField()))
		if err != nil {
			return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("voteverifier verify: %w", err)
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
	// compute public inputs hash
	commonInputs := []*big.Int{vvInputs.ProcessID, vvInputs.CensusRoot}
	commonInputs = append(commonInputs, circuits.MockBallotMode().Serialize()...)
	commonInputs = append(commonInputs, vvInputs.EncryptionPubKey.Serialize()...)
	// pad voters inputs (nullifiers, commitments, addresses)
	addresses := circuits.BigIntArrayToN(vvInputs.Addresses, circuits.VotesPerBatch)
	nullifiers := circuits.BigIntArrayToN(vvInputs.Nullifiers, circuits.VotesPerBatch)
	commitments := circuits.BigIntArrayToN(vvInputs.Commitments, circuits.VotesPerBatch)
	hashInputs := []*big.Int{}
	for i := 0; i < circuits.VotesPerBatch; i++ {
		if i < nValidVoters {
			hashInputs = append(hashInputs, vvInputs.InputsHashes[i])
		} else {
			voterInputs := append(commonInputs, addresses[i], commitments[i], nullifiers[i])
			// TODO: move this to a helper function
			// Dummy encrypted ballots [FieldsPerBallot]{0,1,0,1} for invalid voters
			for j := 0; j < circuits.FieldsPerBallot; j++ {
				voterInputs = append(voterInputs, big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(1))
			}
			hashInput, err := mimc7.Hash(voterInputs, nil)
			if err != nil {
				return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("inputsHash subhash: %w", err)
			}
			hashInputs = append(hashInputs, hashInput)
		}
	}
	// hash the inputs to generate the inputs hash
	inputsHash, err := mimc7.Hash(hashInputs, nil)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("inputsHash final hash: %w", err)
	}
	// init final assignments stuff
	finalAssigments := aggregator.AggregatorCircuit{
		InputsHash: emulated.ValueOf[sw_bn254.ScalarField](inputsHash),
		ValidVotes: aggregator.EncodeProofsSelector(nValidVoters),
		Process: circuits.Process[emulated.Element[sw_bn254.ScalarField]]{
			ID:            emulated.ValueOf[sw_bn254.ScalarField](vvInputs.ProcessID),
			CensusRoot:    emulated.ValueOf[sw_bn254.ScalarField](vvInputs.CensusRoot),
			BallotMode:    circuits.MockBallotModeEmulated(),
			EncryptionKey: vvInputs.EncryptionPubKey.BigIntsToEmulatedElementBN254(),
		},
		Proofs: proofs,
	}
	// set voters final witness stuff
	for i := 0; i < nValidVoters; i++ {
		finalAssigments.Votes[i] = circuits.EmulatedVote[sw_bn254.ScalarField]{
			Nullifier:  emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Nullifiers[i]),
			Commitment: emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Commitments[i]),
			Address:    emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Addresses[i]),
			Ballot:     *vvInputs.Ballots[i].ToGnarkEmulatedBN254(),
		}
	}
	// fix the vote verifier verification key
	fixedVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vvVk)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("voteverifier vk: %w", err)
	}
	// create final placeholder
	finalPlaceholder := aggregator.AggregatorCircuit{
		Proofs:              [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{},
		BaseVerificationKey: fixedVk,
	}
	// fill placeholder and witness with dummy circuits
	finalPlaceholder, finalAssigments, err = aggregator.FillWithDummyFixed(finalPlaceholder, finalAssigments, vvCCS, nValidVoters, persist)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("voteverifier dummy fill: %w", err)
	}

	// TODO: drop this compat-code when previous circuits are also refactored and can do Votes = vvInputs.Votes
	votes := []state.Vote{}
	for i := 0; i < nValidVoters; i++ {
		votes = append(votes, state.Vote{
			Address:    arbo.BigIntToBytes(32, vvInputs.Addresses[i]),
			Commitment: vvInputs.Commitments[i],
			Nullifier:  arbo.BigIntToBytes(32, vvInputs.Nullifiers[i]),
			Ballot:     &vvInputs.Ballots[i],
		})
	}
	res := AggregatorTestResults{
		InputsHash: inputsHash,
		Process: circuits.Process[*big.Int]{
			ID:         vvInputs.ProcessID,
			CensusRoot: vvInputs.CensusRoot,
			// BallotMode:    circuits.BallotMode{},
			EncryptionKey: vvInputs.EncryptionPubKey,
		},
		Votes: votes[:],
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
	return res, finalPlaceholder, finalAssigments, nil
}

// AggregatorInputsWithDummyProof returns the AggregatorTestResults, the placeholder
// and the assignments of a AggregatorCircuit for the processId provided
// generating nValidVoters. If something fails it returns an error.
func AggregatorInputsWithDummyProof(processId []byte, nValidVoters int, persist bool) (
	AggregatorTestResults, aggregator.AggregatorCircuit, aggregator.AggregatorCircuit, error,
) {
	// generate users accounts and census
	vvData := []voteverifiertest.VoterTestData{}
	for i := 0; i < nValidVoters; i++ {
		privKey, pubKey, address, err := ballottest.GenECDSAaccountForTest()
		if err != nil {
			return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("generate accounts: %w", err)
		}
		vvData = append(vvData, voteverifiertest.VoterTestData{
			PrivKey: privKey,
			PubKey:  pubKey,
			Address: address,
		})
	}

	// generate vote verifier inputs
	vvInputs, _, _, err := voteverifiertest.VoteVerifierInputsWithoutProof(vvData, processId)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("voteverifier inputs: %w", err)
	}

	// compile vote verifier circuit
	dummyCCS, err := frontend.Compile(circuits.VoteVerifierCurve.ScalarField(), r1cs.NewBuilder, dummy.PlaceholderWithConstraints(0))
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("voteverifier compile: %w", err)
	}

	// compute public inputs hash
	commonInputs := []*big.Int{vvInputs.ProcessID, vvInputs.CensusRoot}
	commonInputs = append(commonInputs, circuits.MockBallotMode().Serialize()...)
	commonInputs = append(commonInputs, vvInputs.EncryptionPubKey.Serialize()...)
	// pad voters inputs (nullifiers, commitments, addresses)
	addresses := circuits.BigIntArrayToN(vvInputs.Addresses, circuits.VotesPerBatch)
	nullifiers := circuits.BigIntArrayToN(vvInputs.Nullifiers, circuits.VotesPerBatch)
	commitments := circuits.BigIntArrayToN(vvInputs.Commitments, circuits.VotesPerBatch)
	hashInputs := []*big.Int{}
	for i := 0; i < circuits.VotesPerBatch; i++ {
		if i < nValidVoters {
			hashInputs = append(hashInputs, vvInputs.InputsHashes[i])
		} else {
			voterInputs := append(commonInputs, addresses[i], commitments[i], nullifiers[i])
			// TODO: move this to a helper function
			// Dummy encrypted ballots [FieldsPerBallot]{0,1,0,1} for invalid voters
			for j := 0; j < circuits.FieldsPerBallot; j++ {
				voterInputs = append(voterInputs, big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(1))
			}
			hashInput, err := mimc7.Hash(voterInputs, nil)
			if err != nil {
				return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("inputsHash subhash: %w", err)
			}
			hashInputs = append(hashInputs, hashInput)
		}
	}
	// hash the inputs to generate the inputs hash
	inputsHash, err := mimc7.Hash(hashInputs, nil)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("inputsHash final hash: %w", err)
	}

	// init final assignments stuff
	finalAssigments := aggregator.AggregatorCircuit{
		InputsHash: emulated.ValueOf[sw_bn254.ScalarField](inputsHash),
		ValidVotes: aggregator.EncodeProofsSelector(nValidVoters),
		Process: circuits.Process[emulated.Element[sw_bn254.ScalarField]]{
			ID:            emulated.ValueOf[sw_bn254.ScalarField](vvInputs.ProcessID),
			CensusRoot:    emulated.ValueOf[sw_bn254.ScalarField](vvInputs.CensusRoot),
			BallotMode:    circuits.MockBallotModeEmulated(),
			EncryptionKey: vvInputs.EncryptionPubKey.BigIntsToEmulatedElementBN254(),
		},
	}
	// set voters final witness stuff
	for i := 0; i < nValidVoters; i++ {
		finalAssigments.Votes[i] = circuits.EmulatedVote[sw_bn254.ScalarField]{
			Nullifier:  emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Nullifiers[i]),
			Commitment: emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Commitments[i]),
			Address:    emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Addresses[i]),
			Ballot:     *vvInputs.Ballots[i].ToGnarkEmulatedBN254(),
		}
	}
	// create final placeholder
	finalPlaceholder := aggregator.AggregatorCircuit{
		Proofs: [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{},
	}
	// fill placeholder and witness with dummy circuits
	finalPlaceholder, finalAssigments, err = aggregator.FillWithDummyFixed(finalPlaceholder, finalAssigments, dummyCCS, 0, persist)
	if err != nil {
		return AggregatorTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("voteverifier dummy fill: %w", err)
	}

	finalPlaceholder.BaseVerificationKey = finalPlaceholder.DummyVerificationKey

	// TODO: drop this compat-code when previous circuits are also refactored and can do Votes = vvInputs.Votes
	votes := [circuits.VotesPerBatch]state.Vote{}
	for i := range votes {
		votes[i].Address = arbo.BigIntToBytes(32, addresses[i])
		votes[i].Commitment = commitments[i]
		votes[i].Nullifier = arbo.BigIntToBytes(32, nullifiers[i])
		votes[i].Ballot = &vvInputs.Ballots[i]
	}
	res := AggregatorTestResults{
		InputsHash: inputsHash,
		Process: circuits.Process[*big.Int]{
			ID:         vvInputs.ProcessID,
			CensusRoot: vvInputs.CensusRoot,
			// BallotMode:    circuits.BallotMode{},
			EncryptionKey: vvInputs.EncryptionPubKey,
		},
		Votes: votes[:],
	}

	return res, finalPlaceholder, finalAssigments, nil
}
