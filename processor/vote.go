package processor

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
	"github.com/vocdoni/vocdoni-z-sandbox/storage/census"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

type VoteProcessor struct {
	stg    *storage.Storage
	ctx    context.Context
	cancel context.CancelFunc
}

// NewVoteProcessor creates a new VoteProcessor instance with the given storage
// instance.
func NewVoteProcessor(stg *storage.Storage) *VoteProcessor {
	return &VoteProcessor{
		stg: stg,
	}
}

// Start method starts the vote processor. It will process ballots in the
// background. It iterates over the ballots available in the storage and
// generates proofs of the validity of the ballots, storing them back in the
// storage. It will stop processing ballots when the context is cancelled.
func (p *VoteProcessor) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)
	// run the verifier in background until its context is cancelled
	go func() {
		for {
			select {
			case <-p.ctx.Done():
				return
			default:
				// get the next ballot
				ballot, key, err := p.stg.NextBallot()
				if err != nil {
					if err != storage.ErrNoMoreElements {
						log.Errorf("failed to get next ballot: %v", err)
					}
					break
				}
				log.Debugf("new ballot to process for address %s", ballot.Address.String())
				// process the ballot
				verifiedBallot, err := p.ProcessBallot(ballot)
				if err != nil {
					log.Errorf("failed to process ballot: %v", err)
					break
				}
				log.Debugf("ballot processed for address %s", ballot.Address)
				// store the verified ballot
				if err := p.stg.MarkBallotDone(key, verifiedBallot); err != nil {
					log.Errorf("failed to mark ballot done: %v", err)
				}
			}
			time.Sleep(1 * time.Second)
		}
	}()
	return nil
}

// Stop method cancels the context of the vote processor, stopping the
// processing of ballots.
func (p *VoteProcessor) Stop() error {
	p.cancel()
	return nil
}

func (p *VoteProcessor) ProcessBallot(b *storage.Ballot) (*storage.VerifiedBallot, error) {
	// decode the process id
	pid := new(types.ProcessID)
	if err := pid.Unmarshal(b.ProcessID); err != nil {
		return nil, fmt.Errorf("failed to unmarshal process id: %w", err)
	}
	// get the process metadata
	process, err := p.stg.Process(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get process metadata: %w", err)
	}
	processID := crypto.BigToFF(circuits.BallotProofCurve.ScalarField(), b.ProcessID.BigInt().MathBigInt())
	root := arbo.BytesToBigInt(process.Census.CensusRoot)
	// calculate inputs hash
	hashInputs := []*big.Int{}
	hashInputs = append(hashInputs, processID)
	hashInputs = append(hashInputs, root)
	hashInputs = append(hashInputs, circuits.MockBallotMode().Serialize()...)
	hashInputs = append(hashInputs, circuits.EncryptionKeyToCircuit[*big.Int](*process.EncryptionKey).Serialize()...)
	hashInputs = append(hashInputs, b.Address.BigInt().MathBigInt())
	hashInputs = append(hashInputs, b.Commitment.BigInt().MathBigInt())
	hashInputs = append(hashInputs, b.Nullifier.BigInt().MathBigInt())
	hashInputs = append(hashInputs, b.EncryptedBallot.BigInts()...)
	inputHash, err := mimc7.Hash(hashInputs, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to hash inputs: %w", err)
	}
	// unpack census proof siblings to big integers
	siblings, err := census.BigIntSiblings(b.CensusProof.Siblings)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack census proof siblings: %w", err)
	}
	// convert to emulated elements
	emulatedSiblings := [circuits.CensusProofMaxLevels]emulated.Element[sw_bn254.ScalarField]{}
	for i, s := range circuits.BigIntArrayToN(siblings, circuits.CensusProofMaxLevels) {
		emulatedSiblings[i] = emulated.ValueOf[sw_bn254.ScalarField](s)
	}
	// decompress the public key
	pubKey, err := ethcrypto.DecompressPubkey(b.PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress voter public key: %w", err)
	}

	// write debug inputs to file to be used in the test
	// writeForDebug(inputHash, processID, root, b, process, pubKey, siblings)

	// set the circuit assignment
	assignment := voteverifier.VerifyVoteCircuit{
		InputsHash: emulated.ValueOf[sw_bn254.ScalarField](inputHash),
		Vote: circuits.EmulatedVote[sw_bn254.ScalarField]{
			Address:    emulated.ValueOf[sw_bn254.ScalarField](b.Address.BigInt().MathBigInt()),
			Commitment: emulated.ValueOf[sw_bn254.ScalarField](b.Commitment.BigInt().MathBigInt()),
			Nullifier:  emulated.ValueOf[sw_bn254.ScalarField](b.Nullifier.BigInt().MathBigInt()),
			Ballot:     *b.EncryptedBallot.ToGnarkEmulatedBN254(),
		},
		UserWeight: emulated.ValueOf[sw_bn254.ScalarField](b.VoterWeight.BigInt().MathBigInt()),
		Process: circuits.Process[emulated.Element[sw_bn254.ScalarField]]{
			ID:         emulated.ValueOf[sw_bn254.ScalarField](processID),
			CensusRoot: emulated.ValueOf[sw_bn254.ScalarField](root),
			EncryptionKey: circuits.EncryptionKey[emulated.Element[sw_bn254.ScalarField]]{
				PubKey: [2]emulated.Element[sw_bn254.ScalarField]{
					emulated.ValueOf[sw_bn254.ScalarField](process.EncryptionKey.X),
					emulated.ValueOf[sw_bn254.ScalarField](process.EncryptionKey.Y),
				},
			},
			BallotMode: circuits.MockBallotModeEmulated(),
		},
		CensusSiblings: emulatedSiblings,
		Msg:            emulated.ValueOf[emulated.Secp256k1Fr](crypto.SignatureHash(b.BallotInputsHash.BigInt().MathBigInt(), circuits.VoteVerifierCurve.ScalarField())),
		PublicKey: gnarkecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pubKey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pubKey.Y),
		},
		Signature: gnarkecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](b.Signature.R.BigInt().MathBigInt()),
			S: emulated.ValueOf[emulated.Secp256k1Fr](b.Signature.S.BigInt().MathBigInt()),
		},
		CircomProof: b.BallotProof,
	}
	// generate the final proof
	proof, err := assignment.Prove()
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}
	return &storage.VerifiedBallot{
		ProcessID:       b.ProcessID,
		VoterWeight:     b.CensusProof.Weight.MathBigInt(),
		Nullifier:       b.Nullifier,
		Commitment:      b.Commitment,
		EncryptedBallot: b.EncryptedBallot,
		Address:         b.Address,
		Proof:           proof,
	}, nil
}

// func writeForDebug(inputHash, processID, root *big.Int, b *storage.Ballot, p *types.Process, pk *ecdsa.PublicKey, s []*big.Int) {
// 	debugSiblings := []types.HexBytes{}
// 	for _, s := range circuits.BigIntArrayToN(s, circuits.CensusProofMaxLevels) {
// 		if s.Int64() == 0 {
// 			debugSiblings = append(debugSiblings, []byte{0})
// 		} else {
// 			debugSiblings = append(debugSiblings, s.Bytes())
// 		}
// 	}
// 	debugInputs := api.DebugVoteVerifierInputs{
// 		InputHash:      inputHash.Bytes(),
// 		Address:        b.Address,
// 		Commitment:     b.Commitment,
// 		Nullifier:      b.Nullifier,
// 		Weight:         b.VoterWeight,
// 		ProcessID:      processID.Bytes(),
// 		CensusRoot:     root.Bytes(),
// 		Ballot:         &b.EncryptedBallot,
// 		CensusSiblings: debugSiblings,
// 		EncryptionKeyX: p.EncryptionKey.X.Bytes(),
// 		EncryptionKeyY: p.EncryptionKey.Y.Bytes(),
// 		Msg:            b.BallotInputsHash,
// 		PublicKeyX:     pk.X.Bytes(),
// 		PublicKeyY:     pk.Y.Bytes(),
// 		SignatureR:     b.Signature.R,
// 		SignatureS:     b.Signature.S,
// 	}
// 	bDebugInputs, err := json.MarshalIndent(debugInputs, "", "  ")
// 	if err != nil {
// 		log.Errorf("failed to marshal debug inputs: %v", err)
// 		return
// 	}
// 	if err := os.WriteFile("debug_inputs.json", bDebugInputs, 0644); err != nil {
// 		log.Errorf("failed to write debug inputs: %v", err)
// 		return
// 	}
// 	fmt.Println(string(bDebugInputs))
// }
