package aggregatortest

import (
	"math"
	"math/big"

	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	bw6761mimc "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/aggregator"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	voteverifiertest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/voteverifier"
)

// AggregateTestResults struct includes relevant data after AggregateCircuit
// inputs generation, including the encrypted ballots in both formats: matrix
// and plain (for hashing)
type AggregateTestResults struct {
	ProcessId             *big.Int
	CensusRoot            *big.Int
	EncryptionPubKey      [2]*big.Int
	Nullifiers            []*big.Int
	Commitments           []*big.Int
	Addresses             []*big.Int
	EncryptedBallots      [][ballottest.NFields][2][2]*big.Int
	PlainEncryptedBallots []*big.Int
}

// AggregarorInputsForTest returns the AggregateTestResults, the placeholder
// and the assigments of a AggregatorCircuit for the processId provided
// generating nValidVoters. If something fails it returns an error.
func AggregarorInputsForTest(processId []byte, nValidVoters int) (
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
	vvInputs, _, vvAssigments, err := voteverifiertest.VoteVerifierInputsForTest(vvData, processId)
	if err != nil {
		return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
	}
	// generate voters proofs
	finalPlaceholder := aggregator.AggregatorCircuit{}

	totalPlainEncryptedBallots := []*big.Int{}
	proofs := [aggregator.MaxVotes]circuits.InnerProofBLS12377{}
	for i := range vvAssigments {
		// flat encrypted ballots
		for _, b := range vvInputs.EncryptedBallots[i] {
			totalPlainEncryptedBallots = append(totalPlainEncryptedBallots, b[0][0], b[0][1], b[1][0], b[1][1])
		}
		// generate the proof
		proof, err := aggregator.DummyInnerProof(arbo.BytesToBigInt([]byte{0x00}))
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
		proofs[i] = *proof
		finalPlaceholder.InnerProofs[i] = *proof
	}
	// compute public inputs hash
	inputs := []*big.Int{
		vvInputs.CensusRoot,
		vvInputs.ProcessID,
		vvInputs.EncryptionPubKey[0],
		vvInputs.EncryptionPubKey[1],
		big.NewInt(int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.ForceUniqueness)),
		big.NewInt(int64(ballottest.MaxValue)),
		big.NewInt(int64(ballottest.MinValue)),
		big.NewInt(int64(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.MaxCount)),
		big.NewInt(int64(ballottest.CostExp)),
		big.NewInt(int64(ballottest.CostFromWeight)),
	}
	// pad voters inputs (nullifiers, commitments, addresses, plain EncryptedBallots)
	nullifiers := circuits.BigIntArrayToN(vvInputs.Nullifiers, aggregator.MaxVotes)
	commitments := circuits.BigIntArrayToN(vvInputs.Commitments, aggregator.MaxVotes)
	addresses := circuits.BigIntArrayToN(vvInputs.Addresses, aggregator.MaxVotes)
	plainEncryptedBallots := circuits.BigIntArrayToN(totalPlainEncryptedBallots, aggregator.MaxVotes*ballottest.NFields*4)
	// append voters inputs (nullifiers, commitments, addresses, plain EncryptedBallots)
	inputs = append(inputs, nullifiers...)
	inputs = append(inputs, commitments...)
	inputs = append(inputs, addresses...)
	inputs = append(inputs, plainEncryptedBallots...)
	// hash the inputs to generate the inputs hash
	var buf [fr_bw6761.Bytes]byte
	aggregatorHashFn := bw6761mimc.NewMiMC()
	for _, input := range inputs {
		input.FillBytes(buf[:])
		_, err := aggregatorHashFn.Write(buf[:])
		if err != nil {
			return AggregateTestResults{}, aggregator.AggregatorCircuit{}, aggregator.AggregatorCircuit{}, err
		}
	}
	publicHash := new(big.Int).SetBytes(aggregatorHashFn.Sum(nil))
	// init final assigments stuff
	finalAssigments := aggregator.AggregatorCircuit{
		InputsHash: publicHash,
		ValidVotes: aggregator.EncodeProofsSelector(nValidVoters),
		BallotMode: circuits.BallotMode[frontend.Variable]{
			MaxCount:        ballottest.MaxCount,
			ForceUniqueness: ballottest.ForceUniqueness,
			MaxValue:        ballottest.MaxValue,
			MinValue:        ballottest.MinValue,
			MaxTotalCost:    int(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * ballottest.MaxCount,
			MinTotalCost:    ballottest.MaxCount,
			CostExp:         ballottest.CostExp,
			CostFromWeight:  ballottest.CostFromWeight,
			EncryptionPubKey: [2]frontend.Variable{
				vvInputs.EncryptionPubKey[0],
				vvInputs.EncryptionPubKey[1],
			},
		},
		ProcessId:   vvInputs.ProcessID,
		CensusRoot:  vvInputs.CensusRoot,
		InnerProofs: proofs,
	}
	// set voters final witness stuff
	for i := 0; i < nValidVoters; i++ {
		finalAssigments.Nullifiers[i] = vvInputs.Nullifiers[i]
		finalAssigments.Commitments[i] = vvInputs.Commitments[i]
		finalAssigments.Addresses[i] = vvInputs.Addresses[i]
		for j := 0; j < ballottest.NFields; j++ {
			for n := 0; n < 2; n++ {
				for m := 0; m < 2; m++ {
					finalAssigments.EncryptedBallots[i][j][n][m] = vvInputs.EncryptedBallots[i][j][n][m]
				}
			}
		}
	}
	// create final placeholder
	return AggregateTestResults{
		ProcessId:             vvInputs.ProcessID,
		CensusRoot:            vvInputs.CensusRoot,
		EncryptionPubKey:      vvInputs.EncryptionPubKey,
		Nullifiers:            nullifiers,
		Commitments:           commitments,
		Addresses:             addresses,
		EncryptedBallots:      vvInputs.EncryptedBallots,
		PlainEncryptedBallots: plainEncryptedBallots,
	}, finalPlaceholder, finalAssigments, nil
}
