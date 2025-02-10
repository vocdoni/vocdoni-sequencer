package aggregatortest

import (
	"fmt"
	"math/big"

	gecc "github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	voteverifiertest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/voteverifier"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
)

// AggregateTestResults struct includes relevant data after AggregateCircuit
// inputs generation, including the encrypted ballots in both formats: matrix
// and plain (for hashing)
type AggregateTestResults struct {
	InputsHash            *big.Int
	ProcessId             *big.Int
	CensusRoot            *big.Int
	EncryptionPubKey      circuits.EncryptionKey[*big.Int]
	Nullifiers            []*big.Int
	Commitments           []*big.Int
	Addresses             []*big.Int
	EncryptedBallots      []elgamal.Ballot
	PlainEncryptedBallots []*big.Int
}

/*
TODO: Fix and refactor this function

func LocalInputsForTest(nValidVoters int) (AggregateTestResults, aggregator.AggregatorCircuit, aggregator.AggregatorCircuit, error) {
	// dummy vkey
	dummyVkFd, err := os.Open("dummy.vkey")
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	dummyVk := groth16.NewVerifyingKey(gecc.BLS12_377)
	if _, err := dummyVk.ReadFrom(dummyVkFd); err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	recursiveDummyVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](dummyVk)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// dummy proof
	dummyProofFd, err := os.Open("dummy.proof")
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	dummyProof := groth16.NewProof(gecc.BLS12_377)
	if _, err := dummyProof.ReadFrom(dummyProofFd); err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	recursiveDummyProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyProof)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// base vkey
	baseVkFd, err := os.Open("vote_verifier.vkey")
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	baseVk := groth16.NewVerifyingKey(gecc.BLS12_377)
	if _, err := baseVk.ReadFrom(baseVkFd); err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	recursiveBaseVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](baseVk)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// proofs and witnesses
	proofs := [aggregator.MaxVotes]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	for i := 0; i < aggregator.MaxVotes; i++ {
		if i < nValidVoters {
			proofFd, err := os.Open(fmt.Sprintf("vote_verifier_%d.proof", i))
			if err != nil {
				return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
			}
			proof := groth16.NewProof(gecc.BLS12_377)
			if _, err := proof.ReadFrom(proofFd); err != nil {
				return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
			}
			recursiveProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
			if err != nil {
				return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
			}
			proofs[i] = recursiveProof
		} else {
			proofs[i] = recursiveDummyProof
		}
	}
	// inputs
	resultsFd, err := os.Open("aggregator_test_inputs.json")
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	results := AggregateTestResults{}
	if err := json.NewDecoder(resultsFd).Decode(&results); err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// load constrain system
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &voteverifier.VerifyVoteCircuit{})
	if err != nil {
		log.Println("error compiling constraint system", err)
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	builder, err := r1cs.NewBuilder(ecc.BLS12_377.ScalarField(), frontend.CompileConfig{
		CompressThreshold: 300,
	})
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	ccs, err := builder.Compile()
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	if _, err := ccs.ReadFrom(fdCCS); err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
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

// AggregarorInputsForTest returns the AggregateTestResults, the placeholder
// and the assignments of a AggregatorCircuit for the processId provided
// generating nValidVoters. If something fails it returns an error.
func AggregarorInputsForTest(processId []byte, nValidVoters int, persist bool) (
	AggregateTestResults, aggregator.AggregatorCircuit, aggregator.AggregatorCircuit, error,
) {
	// generate users accounts and census
	vvData := []voteverifiertest.VoterTestData{}
	for i := 0; i < nValidVoters; i++ {
		privKey, pubKey, address, err := ballottest.GenECDSAaccountForTest()
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
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
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// compile vote verifier circuit
	vvCCS, err := frontend.Compile(gecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &vvPlaceholder)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	vvPk, vvVk, err := groth16.Setup(vvCCS)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
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
	totalPlainEncryptedBallots := []*big.Int{}
	proofs := [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}
	for i := range vvAssigments {
		// flat encrypted ballots
		for _, b := range vvInputs.EncryptedBallots {
			totalPlainEncryptedBallots = append(totalPlainEncryptedBallots, b.BigInts()...)
		}
		// parse the witness to the circuit
		fullWitness, err := frontend.NewWitness(&vvAssigments[i], gecc.BLS12_377.ScalarField())
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		// generate the proof
		proof, err := groth16.Prove(vvCCS, vvPk, fullWitness, stdgroth16.GetNativeProverOptions(gecc.BW6_761.ScalarField(), gecc.BLS12_377.ScalarField()))
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, fmt.Errorf("err proving proof %d: %w", i, err)
		}
		// convert the proof to the circuit proof type
		proofs[i], err = stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		// convert the public inputs to the circuit public inputs type
		publicWitness, err := fullWitness.Public()
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		err = groth16.Verify(proof, vvVk, publicWitness, stdgroth16.GetNativeVerifierOptions(gecc.BW6_761.ScalarField(), gecc.BLS12_377.ScalarField()))
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
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
	commonInputs := []*big.Int{
		vvInputs.ProcessID,
		vvInputs.CensusRoot,
	}
	commonInputs = append(commonInputs, vvInputs.EncryptionPubKey.Serialize()...)
	commonInputs = append(commonInputs, circuits.MockBallotMode().Serialize()...)
	// pad voters inputs (nullifiers, commitments, addresses, plain EncryptedBallots)
	addresses := circuits.BigIntArrayToN(vvInputs.Addresses, circuits.VotesPerBatch)
	nullifiers := circuits.BigIntArrayToN(vvInputs.Nullifiers, circuits.VotesPerBatch)
	commitments := circuits.BigIntArrayToN(vvInputs.Commitments, circuits.VotesPerBatch)
	plainEncryptedBallots := circuits.BigIntArrayToN(totalPlainEncryptedBallots, circuits.VotesPerBatch*circuits.FieldsPerBallot*4)
	hashInputs := []*big.Int{}
	for i := 0; i < circuits.VotesPerBatch; i++ {
		voterInputs := append(commonInputs, addresses[i], nullifiers[i], commitments[i])
		if i < nValidVoters {
			voterInputs = append(voterInputs, vvInputs.EncryptedBallots[i].BigInts()...)
		} else {
			// TODO: move this to a helper function
			// Dummy encrypted ballots [FieldsPerBallot]{0,1,0,1} for invalid voters
			for j := 0; j < circuits.FieldsPerBallot; j++ {
				voterInputs = append(voterInputs, big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(1))
			}
		}
		hashInput, err := mimc7.Hash(voterInputs, nil)
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		hashInputs = append(hashInputs, hashInput)
	}
	// hash the inputs to generate the inputs hash
	inputsHash, err := mimc7.Hash(hashInputs, nil)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
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
		finalAssigments.Votes[i].Nullifier = emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Nullifiers[i])
		finalAssigments.Votes[i].Commitment = emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Commitments[i])
		finalAssigments.Votes[i].Address = emulated.ValueOf[sw_bn254.ScalarField](vvInputs.Addresses[i])
		finalAssigments.Votes[i].Ballot = *vvInputs.EncryptedBallots[i].ToGnarkEmulatedBN254()
	}
	// fix the vote verifier verification key
	fixedVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vvVk)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// create final placeholder
	finalPlaceholder := aggregator.AggregatorCircuit{
		Proofs:              [circuits.VotesPerBatch]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{},
		BaseVerificationKey: fixedVk,
	}
	// fill placeholder and witness with dummy circuits
	finalPlaceholder, finalAssigments, err = aggregator.FillWithDummyFixed(finalPlaceholder, finalAssigments, vvCCS, nValidVoters, persist)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	res := AggregateTestResults{
		InputsHash:            inputsHash,
		ProcessId:             vvInputs.ProcessID,
		CensusRoot:            vvInputs.CensusRoot,
		EncryptionPubKey:      vvInputs.EncryptionPubKey,
		Nullifiers:            nullifiers,
		Commitments:           commitments,
		Addresses:             addresses,
		EncryptedBallots:      vvInputs.EncryptedBallots,
		PlainEncryptedBallots: plainEncryptedBallots,
	}

	/*
		TODO: uncomment this block when the LocalInputsForTest function is fixed
		if persist {
			// persist the results
			bRes, err := res.MarshalJSON()
			if err != nil {
				log.Println("error marshalling AggregateTestResults", err)
				return res, finalPlaceholder, finalAssigments, nil
			}
			if err := os.WriteFile("aggregator_test_inputs.json", bRes, 0o644); err != nil {
				log.Println("error writing AggregateTestResults", err)
			}
		}
	*/
	return res, finalPlaceholder, finalAssigments, nil
}
