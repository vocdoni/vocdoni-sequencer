package voteverifier

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/arbo"
	primitivestest "github.com/vocdoni/gnark-crypto-primitives/testutil"
	circomtest "github.com/vocdoni/vocdoni-z-sandbox/circuits/circom"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"go.vocdoni.io/dvote/util"
)

type VoteVerifierResults struct {
	EncryptionPubKey [2]*big.Int
	ProcessID        []byte
	CensusRoot       *big.Int
	Nullifiers       []*big.Int
	Commitments      []*big.Int
	EncryptedBallots [][circomtest.NFields][2][2]*big.Int
}

type VoterData struct {
	PrivKey *ecdsa.PrivateKey
	PubKey  ecdsa.PublicKey
	Address common.Address
}

// GenerateInputs returns the census root, the placeholder of the
// circuit and it assigments.
func GenerateInputs(votersData []VoterData) (*VoteVerifierResults, VerifyVoteCircuit, []VerifyVoteCircuit, error) {
	circomPlaceholder, err := circomtest.Circom2GnarkPlaceholder()
	if err != nil {
		return nil, VerifyVoteCircuit{}, nil, err
	}
	bAddresses, bWeights := [][]byte{}, [][]byte{}
	for _, voter := range votersData {
		bAddresses = append(bAddresses, voter.Address.Bytes())
		bWeights = append(bWeights, new(big.Int).SetInt64(int64(circomtest.Weight)).Bytes())
	}
	// generate a test census
	testCensus, err := primitivestest.GenerateCensusProofForTest(primitivestest.CensusTestConfig{
		Dir:           "../assets/census",
		ValidSiblings: 10,
		TotalSiblings: circomtest.NLevels,
		KeyLen:        20,
		Hash:          arbo.HashFunctionMiMC_BLS12_377,
		BaseFiled:     arbo.BLS12377BaseField,
	}, bAddresses, bWeights)
	if err != nil {
		return nil, VerifyVoteCircuit{}, nil, err
	}
	// common data
	fields := circomtest.GenerateBallotFields(circomtest.MaxCount, circomtest.MaxValue, circomtest.MinValue, circomtest.ForceUniqueness > 0)
	processID := util.RandomBytes(20)
	encryptionKey := circomtest.GenerateEncryptionTestKey()
	encryptionKeyX, encryptionKeyY := encryptionKey.Point()
	// circuits assigments, voters data and proofs
	var assigments []VerifyVoteCircuit
	nullifiers, commitments := []*big.Int{}, []*big.Int{}
	encryptedBallots := [][circomtest.NFields][2][2]*big.Int{}
	for _, voter := range votersData {
		// encrypt the ballots
		k, err := elgamal.RandK()
		if err != nil {
			return nil, VerifyVoteCircuit{}, nil, err
		}
		cipherfields, plainCipherfields := circomtest.CipherBallotFields(fields, circomtest.NFields, encryptionKey, k)
		// generate and store voter nullifier and commitments
		secret := util.RandomBytes(16)
		commitment, nullifier, err := circomtest.MockedCommitmentAndNullifier(voter.Address.Bytes(), processID, secret)
		if err != nil {
			return nil, VerifyVoteCircuit{}, nil, err
		}
		nullifiers = append(nullifiers, nullifier)
		commitments = append(commitments, commitment)
		// store voter ballots
		voterEncryptedBallots := [circomtest.NFields][2][2]*big.Int{}
		for i := range voterEncryptedBallots {
			c1X, _ := new(big.Int).SetString(cipherfields[i][0][0], 10)
			c1Y, _ := new(big.Int).SetString(cipherfields[i][0][1], 10)
			c2X, _ := new(big.Int).SetString(cipherfields[i][1][0], 10)
			c2Y, _ := new(big.Int).SetString(cipherfields[i][1][1], 10)
			voterEncryptedBallots[i] = [2][2]*big.Int{{c1X, c1Y}, {c2X, c2Y}}
		}
		encryptedBallots = append(encryptedBallots, voterEncryptedBallots)
		// group the circom inputs to hash
		bigCircomInputs := []*big.Int{
			big.NewInt(int64(circomtest.MaxCount)),
			big.NewInt(int64(circomtest.ForceUniqueness)),
			big.NewInt(int64(circomtest.MaxValue)),
			big.NewInt(int64(circomtest.MinValue)),
			big.NewInt(int64(math.Pow(float64(circomtest.MaxValue), float64(circomtest.CostExp))) * int64(circomtest.MaxCount)),
			big.NewInt(int64(circomtest.MaxCount)),
			big.NewInt(int64(circomtest.CostExp)),
			big.NewInt(int64(circomtest.CostFromWeight)),
			arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(voter.Address.Bytes())),
			big.NewInt(int64(circomtest.Weight)),
			arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(processID)),
			encryptionKeyX,
			encryptionKeyY,
			nullifier,
			commitment,
		}
		bigCircomInputs = append(bigCircomInputs, plainCipherfields...)
		circomInputsHash, err := mimc7.Hash(bigCircomInputs, nil)
		if err != nil {
			return nil, VerifyVoteCircuit{}, nil, err
		}
		// transform the inputs hash to the field of the curve used by the circuit,
		// if it is not done, the circuit will transform it during witness
		// calculation and the hash will be different
		// the resulting hash should have 32 bytes so if it does'nt, fill with 0s
		blsCircomInputsHash := arbo.BigToFF(ecc.BLS12_377.ScalarField(), circomInputsHash)
		if b := blsCircomInputsHash.Bytes(); len(b) < 32 {
			for len(b) < 32 {
				b = append(b, 0)
			}
			blsCircomInputsHash.SetBytes(b)
		}
		// sign the inputs hash with the private key
		rSign, sSign, err := circomtest.SignECDSA(voter.PrivKey, blsCircomInputsHash.Bytes())
		if err != nil {
			return nil, VerifyVoteCircuit{}, nil, err
		}
		// init circom inputs
		circomInputs := map[string]any{
			"fields":           circomtest.BigIntArrayToStringArray(fields, circomtest.NFields),
			"max_count":        fmt.Sprint(circomtest.MaxCount),
			"force_uniqueness": fmt.Sprint(circomtest.ForceUniqueness),
			"max_value":        fmt.Sprint(circomtest.MaxValue),
			"min_value":        fmt.Sprint(circomtest.MinValue),
			"max_total_cost":   fmt.Sprint(int(math.Pow(float64(circomtest.MaxValue), float64(circomtest.CostExp))) * circomtest.MaxCount),
			"min_total_cost":   fmt.Sprint(circomtest.MaxCount),
			"cost_exp":         fmt.Sprint(circomtest.CostExp),
			"cost_from_weight": fmt.Sprint(circomtest.CostFromWeight),
			"address":          arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(voter.Address.Bytes())).String(),
			"weight":           fmt.Sprint(circomtest.Weight),
			"process_id":       arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(processID)).String(),
			"pk":               []string{encryptionKeyX.String(), encryptionKeyY.String()},
			"k":                k.String(),
			"cipherfields":     cipherfields,
			"nullifier":        nullifier.String(),
			"commitment":       commitment.String(),
			"secret":           arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(secret)).String(),
			"inputs_hash":      circomInputsHash.String(),
		}
		bCircomInputs, err := json.Marshal(circomInputs)
		if err != nil {
			return nil, VerifyVoteCircuit{}, nil, err
		}
		// create the proof
		circomProof, err := circomtest.Circom2GnarkProof(bCircomInputs)
		if err != nil {
			return nil, VerifyVoteCircuit{}, nil, err
		}
		// transform cipherfields to gnark frontend.Variable
		emulatedBallots := [circomtest.NFields][2][2]emulated.Element[sw_bn254.ScalarField]{}
		for i, c := range cipherfields {
			emulatedBallots[i] = [2][2]emulated.Element[sw_bn254.ScalarField]{
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
		fSiblings := [circomtest.NLevels]frontend.Variable{}
		for i, s := range testCensus.Proofs[0].Siblings {
			fSiblings[i] = frontend.Variable(s)
		}
		// hash the inputs of gnark circuit (circom inputs hash + census root)
		hFn := mimc.NewMiMC()
		hFn.Write(blsCircomInputsHash.Bytes())
		hFn.Write(testCensus.Root.Bytes())
		inputsHash := new(big.Int).SetBytes(hFn.Sum(nil))
		// compose circuit placeholders
		assigments = append(assigments, VerifyVoteCircuit{
			InputsHash: inputsHash,
			// circom inputs
			MaxCount:        emulated.ValueOf[sw_bn254.ScalarField](circomtest.MaxCount),
			ForceUniqueness: emulated.ValueOf[sw_bn254.ScalarField](circomtest.ForceUniqueness),
			MaxValue:        emulated.ValueOf[sw_bn254.ScalarField](circomtest.MaxValue),
			MinValue:        emulated.ValueOf[sw_bn254.ScalarField](circomtest.MinValue),
			MaxTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](int(math.Pow(float64(circomtest.MaxValue), float64(circomtest.CostExp))) * circomtest.MaxCount),
			MinTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](circomtest.MaxCount),
			CostExp:         emulated.ValueOf[sw_bn254.ScalarField](circomtest.CostExp),
			CostFromWeight:  emulated.ValueOf[sw_bn254.ScalarField](circomtest.CostFromWeight),
			Address:         emulated.ValueOf[sw_bn254.ScalarField](voter.Address.Big()),
			UserWeight:      emulated.ValueOf[sw_bn254.ScalarField](circomtest.Weight),
			EncryptionPubKey: [2]emulated.Element[sw_bn254.ScalarField]{
				emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyX),
				emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyY),
			},
			Nullifier:       emulated.ValueOf[sw_bn254.ScalarField](nullifier),
			Commitment:      emulated.ValueOf[sw_bn254.ScalarField](commitment),
			ProcessId:       emulated.ValueOf[sw_bn254.ScalarField](arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(processID))),
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
			CircomProof:            circomProof.Proof,
			CircomPublicInputsHash: circomProof.PublicInputs,
		})
	}

	return &VoteVerifierResults{
			EncryptionPubKey: [2]*big.Int{encryptionKeyX, encryptionKeyY},
			ProcessID:        processID,
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
