package voteverifier

import (
	"crypto/ecdsa"
	"fmt"
	"math"
	"math/big"

	gecc "github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/vocdoni/arbo"
	primitivestest "github.com/vocdoni/gnark-crypto-primitives/testutil"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	ballottest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test/ballotproof"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	"go.vocdoni.io/dvote/util"
)

// VoteVerifierTestResults struct includes relevant data after VerifyVoteCircuit
// inputs generation
type VoteVerifierTestResults struct {
	EncryptionPubKey [2]*big.Int
	Addresses        []*big.Int
	ProcessID        *big.Int
	CensusRoot       *big.Int
	Nullifiers       []*big.Int
	Commitments      []*big.Int
	EncryptedBallots [][ballottest.NFields][2][2]*big.Int
}

// VoterTestData struct includes the information required to generate the test
// inputs for the VerifyVoteCircuit.
type VoterTestData struct {
	PrivKey *ecdsa.PrivateKey
	PubKey  ecdsa.PublicKey
	Address common.Address
}

// VoteVerifierInputsForTest returns the VoteVerifierTestResults, the placeholder
// and the assigments for a VerifyVoteCircuit including the provided voters. If
// processId is nil, it will be randomly generated. If something fails it
// returns an error.
func VoteVerifierInputsForTest(votersData []VoterTestData, processId []byte) (
	*VoteVerifierTestResults, VerifyVoteCircuit,
	[]VerifyVoteCircuit, error,
) {
	circomPlaceholder, err := circuits.Circom2GnarkPlaceholder(ballottest.TestCircomVerificationKey)
	if err != nil {
		return nil, VerifyVoteCircuit{}, nil, err
	}
	bAddresses, bWeights := [][]byte{}, [][]byte{}
	for _, voter := range votersData {
		bAddresses = append(bAddresses, voter.Address.Bytes())
		bWeights = append(bWeights, new(big.Int).SetInt64(int64(ballottest.Weight)).Bytes())
	}
	// generate a test census
	testCensus, err := primitivestest.GenerateCensusProofForTest(primitivestest.CensusTestConfig{
		Dir:           fmt.Sprintf("../assets/census%d", util.RandomInt(0, 1000)),
		ValidSiblings: 10,
		TotalSiblings: ballottest.NLevels,
		KeyLen:        20,
		Hash:          arbo.HashFunctionMiMC_BLS12_377,
		BaseField:     arbo.BLS12377BaseField,
	}, bAddresses, bWeights)
	if err != nil {
		return nil, VerifyVoteCircuit{}, nil, err
	}
	// common data
	if processId != nil {
		processId = util.RandomBytes(20)
	}
	encryptionKey := ballottest.GenEncryptionKeyForTest()
	encryptionKeyX, encryptionKeyY := encryptionKey.Point()
	// circuits assigments, voters data and proofs
	var assigments []VerifyVoteCircuit
	addresses, nullifiers, commitments := []*big.Int{}, []*big.Int{}, []*big.Int{}
	encryptedBallots := [][ballottest.NFields][2][2]*big.Int{}
	var finalProcessID *big.Int
	for i, voter := range votersData {
		voterProof, err := ballottest.BallotProofForTest(voter.Address.Bytes(), processId, encryptionKey)
		if err != nil {
			return nil, VerifyVoteCircuit{}, nil, err
		}
		if finalProcessID == nil {
			finalProcessID = voterProof.ProcessID
		}
		addresses = append(addresses, voterProof.Address)
		nullifiers = append(nullifiers, voterProof.Nullifier)
		commitments = append(commitments, voterProof.Commitment)
		encryptedBallots = append(encryptedBallots, voterProof.EncryptedFields)
		// convert the circom inputs hash to the field of the curve used by the
		// circuit as input for MIMC hash
		blsCircomInputsHash := circuits.BigIntToMIMCHash(voterProof.InputsHash, gecc.BLS12_377.ScalarField())
		// sign the inputs hash with the private key
		rSign, sSign, err := ballottest.SignECDSAForTest(voter.PrivKey, blsCircomInputsHash)
		if err != nil {
			return nil, VerifyVoteCircuit{}, nil, err
		}
		// transform encryptedBallots to gnark frontend.Variable
		emulatedBallots := [ballottest.NFields][2][2]emulated.Element[sw_bn254.ScalarField]{}
		for j, c := range voterProof.EncryptedFields {
			emulatedBallots[j] = [2][2]emulated.Element[sw_bn254.ScalarField]{
				{
					emulated.ValueOf[sw_bn254.ScalarField](c[0][0]),
					emulated.ValueOf[sw_bn254.ScalarField](c[0][1]),
				},
				{
					emulated.ValueOf[sw_bn254.ScalarField](c[1][0]),
					emulated.ValueOf[sw_bn254.ScalarField](c[1][1]),
				},
			}
		}
		// transform siblings to gnark frontend.Variable
		fSiblings := [ballottest.NLevels]frontend.Variable{}
		for j, s := range testCensus.Proofs[i].Siblings {
			fSiblings[j] = frontend.Variable(s)
		}
		// hash the inputs of gnark circuit (except weight and including census root)
		hashInputs := append([]*big.Int{
			testCensus.Root,
			voterProof.ProcessID,
			encryptionKeyX,
			encryptionKeyY,
			new(big.Int).SetInt64(int64(ballottest.MaxCount)),
			new(big.Int).SetInt64(int64(ballottest.ForceUniqueness)),
			new(big.Int).SetInt64(int64(ballottest.MaxValue)),
			new(big.Int).SetInt64(int64(ballottest.MinValue)),
			new(big.Int).SetInt64(int64(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * int64(ballottest.MaxCount)),
			new(big.Int).SetInt64(int64(ballottest.MaxCount)),
			new(big.Int).SetInt64(int64(ballottest.CostExp)),
			new(big.Int).SetInt64(int64(ballottest.CostFromWeight)),
			voterProof.Address,
			voterProof.Nullifier,
			voterProof.Commitment,
		}, voterProof.PlainEcryptedFields...)
		// hash the inputs to generate the inputs hash
		var buf [fr_bls12377.Bytes]byte
		voteVerifierHashFn := mimc.NewMiMC()
		for _, input := range hashInputs {
			ffInput := ecc.BigToFF(gecc.BLS12_377.ScalarField(), input)
			ffInput.FillBytes(buf[:])
			if _, err := voteVerifierHashFn.Write(buf[:]); err != nil {
				return nil, VerifyVoteCircuit{}, nil, err
			}
		}
		inputsHash := new(big.Int).SetBytes(voteVerifierHashFn.Sum(nil))
		// compose circuit placeholders
		assigments = append(assigments, VerifyVoteCircuit{
			InputsHash: inputsHash,
			// circom inputs
			BallotMode: circuits.BallotMode[emulated.Element[sw_bn254.ScalarField]]{
				MaxCount:        emulated.ValueOf[sw_bn254.ScalarField](ballottest.MaxCount),
				ForceUniqueness: emulated.ValueOf[sw_bn254.ScalarField](ballottest.ForceUniqueness),
				MaxValue:        emulated.ValueOf[sw_bn254.ScalarField](ballottest.MaxValue),
				MinValue:        emulated.ValueOf[sw_bn254.ScalarField](ballottest.MinValue),
				MaxTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](int(math.Pow(float64(ballottest.MaxValue), float64(ballottest.CostExp))) * ballottest.MaxCount),
				MinTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](ballottest.MaxCount),
				CostExp:         emulated.ValueOf[sw_bn254.ScalarField](ballottest.CostExp),
				CostFromWeight:  emulated.ValueOf[sw_bn254.ScalarField](ballottest.CostFromWeight),
				EncryptionPubKey: [2]emulated.Element[sw_bn254.ScalarField]{
					emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyX),
					emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyY),
				},
			},
			Address:         emulated.ValueOf[sw_bn254.ScalarField](voterProof.Address),
			UserWeight:      emulated.ValueOf[sw_bn254.ScalarField](ballottest.Weight),
			Nullifier:       emulated.ValueOf[sw_bn254.ScalarField](voterProof.Nullifier),
			Commitment:      emulated.ValueOf[sw_bn254.ScalarField](voterProof.Commitment),
			ProcessId:       emulated.ValueOf[sw_bn254.ScalarField](voterProof.ProcessID),
			EncryptedBallot: emulatedBallots,
			// census proof
			CensusRoot:     testCensus.Root,
			CensusSiblings: fSiblings,
			// signature
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](blsCircomInputsHash),
			PublicKey: gnarkecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](voter.PubKey.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](voter.PubKey.Y),
			},
			Signature: gnarkecdsa.Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](rSign),
				S: emulated.ValueOf[emulated.Secp256k1Fr](sSign),
			},
			// circom proof
			CircomProof:            voterProof.Proof.Proof,
			CircomPublicInputsHash: voterProof.Proof.PublicInputs,
		})
	}

	return &VoteVerifierTestResults{
			EncryptionPubKey: [2]*big.Int{encryptionKeyX, encryptionKeyY},
			Addresses:        addresses,
			ProcessID:        finalProcessID,
			CensusRoot:       testCensus.Root,
			Nullifiers:       nullifiers,
			Commitments:      commitments,
			EncryptedBallots: encryptedBallots,
		}, VerifyVoteCircuit{
			CircomVerificationKey:  circomPlaceholder.Vk,
			CircomProof:            circomPlaceholder.Proof,
			CircomPublicInputsHash: circomPlaceholder.Witness,
		}, assigments, nil
}
