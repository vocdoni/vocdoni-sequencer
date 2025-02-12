package processor

import (
	"bytes"
	"context"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	gecc "github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/voteverifier"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/storage"
	"github.com/vocdoni/vocdoni-z-sandbox/storage/census"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

type VoteProcessor struct {
	s      *storage.Storage
	ctx    context.Context
	cancel context.CancelFunc
}

// NewVoteProcessor creates a new VoteProcessor instance with the given storage
// instance.
func NewVoteProcessor(s *storage.Storage) *VoteProcessor {
	return &VoteProcessor{
		s: s,
	}
}

// Start method starts the vote processor. It will process ballots in the
// background. It iterates over the ballots available in the storage and
// generates proofs of the validity of the ballots, storing them back in the
// storage. It will stop processing ballots when the context is cancelled.
func (p *VoteProcessor) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)
	if err := voteverifier.Artifacts.LoadAll(); err != nil {
		return err
	}
	// run the verifier in background until its context is cancelled
	go func() {
		for {
			select {
			case <-p.ctx.Done():
				return
			default:
				// get the next ballot
				ballot, key, err := p.s.NextBallot()
				if err != nil {
					if err != storage.ErrNoMoreElements {
						log.Errorf("failed to get next ballot: %v", err)
					}
					continue
				}
				// process the ballot
				verifiedBallot, err := p.ProcessBallot(ballot)
				if err != nil {
					log.Errorf("failed to process ballot: %v", err)
					continue
				}
				// store the verified ballot
				if err := p.s.MarkBallotDone(key, verifiedBallot); err != nil {
					log.Errorf("failed to mark ballot done: %v", err)
				}
			}
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
		return nil, err
	}
	// get the process metadata
	process, err := p.s.Process(pid)
	if err != nil {
		return nil, err
	}
	// calculate inputs hash
	hashInputs := []*big.Int{}
	hashInputs = append(hashInputs, b.ProcessID.BigInt().MathBigInt())
	hashInputs = append(hashInputs, b.CensusProof.Root.BigInt().MathBigInt())
	hashInputs = append(hashInputs, circuits.BallotModeToCircuit[*big.Int](*process.BallotMode).Serialize()...)
	hashInputs = append(hashInputs, circuits.EncryptionKeyToCircuit[*big.Int](*process.EncryptionKey).Serialize()...)
	hashInputs = append(hashInputs, b.Address.BigInt().MathBigInt())
	hashInputs = append(hashInputs, b.Commitment.BigInt().MathBigInt())
	hashInputs = append(hashInputs, b.Nullifier.BigInt().MathBigInt())
	hashInputs = append(hashInputs, b.EncryptedBallot.BigInts()...)
	inputHash, err := mimc7.Hash(hashInputs, nil)
	if err != nil {
		return nil, err
	}
	// unpack census proof siblings to big integers
	siblings, err := census.BigIntSiblings(b.CensusProof.Siblings)
	if err != nil {
		return nil, err
	}
	// convert to emulated elements
	emulatedSiblings := [circuits.CensusProofMaxLevels]emulated.Element[sw_bn254.ScalarField]{}
	for j, s := range circuits.BigIntArrayToN(siblings, circuits.CensusProofMaxLevels) {
		emulatedSiblings[j] = emulated.ValueOf[sw_bn254.ScalarField](s)
	}
	// decompress the public key
	pubKey, err := ethcrypto.DecompressPubkey(b.PubKey)
	if err != nil {
		return nil, err
	}
	// set the circuit assignments
	assigment := voteverifier.VerifyVoteCircuit{
		InputsHash: emulated.ValueOf[sw_bn254.ScalarField](inputHash),
		Vote: circuits.EmulatedVote[sw_bn254.ScalarField]{
			Address:    emulated.ValueOf[sw_bn254.ScalarField](b.Address.BigInt().MathBigInt()),
			Nullifier:  emulated.ValueOf[sw_bn254.ScalarField](b.Nullifier.BigInt().MathBigInt()),
			Commitment: emulated.ValueOf[sw_bn254.ScalarField](b.Commitment.BigInt().MathBigInt()),
			Ballot:     *b.EncryptedBallot.ToGnarkEmulatedBN254(),
		},
		UserWeight: emulated.ValueOf[sw_bn254.ScalarField](b.CensusProof.Weight.MathBigInt()),
		Process: circuits.Process[emulated.Element[sw_bn254.ScalarField]]{
			ID:            emulated.ValueOf[sw_bn254.ScalarField](b.ProcessID.BigInt().MathBigInt()),
			CensusRoot:    emulated.ValueOf[sw_bn254.ScalarField](b.CensusProof.Root.BigInt().MathBigInt()),
			EncryptionKey: circuits.EncryptionKeyToCircuit[emulated.Element[sw_bn254.ScalarField]](*process.EncryptionKey),
			BallotMode:    circuits.BallotModeToCircuit[emulated.Element[sw_bn254.ScalarField]](*process.BallotMode),
		},
		CensusSiblings: emulatedSiblings,
		Msg:            emulated.ValueOf[emulated.Secp256k1Fr](crypto.SignatureHash(b.BallotInputsHash.BigInt().MathBigInt(), gecc.BLS12_377.ScalarField())),
		PublicKey: gnarkecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pubKey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pubKey.Y),
		},
		Signature: gnarkecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](b.Signature.R.BigInt().MathBigInt()),
			S: emulated.ValueOf[emulated.Secp256k1Fr](b.Signature.S.BigInt().MathBigInt()),
		},
		CircomProof: circuits.InnerProofBN254{
			VK:    b.BallotProof.Vk,
			Proof: b.BallotProof.Proof,
		},
	}
	// load circuit artifacts content
	if err := voteverifier.Artifacts.LoadAll(); err != nil {
		return nil, err
	}
	// decode the circuit definition (constrain system)
	ccs := groth16.NewCS(ecc.BLS12_377)
	ccsReader := bytes.NewReader(voteverifier.Artifacts.CircuitDefinition())
	if _, err := ccs.ReadFrom(ccsReader); err != nil {
		return nil, err
	}
	// decode the proving key
	pk := groth16.NewProvingKey(ecc.BLS12_377)
	pkReader := bytes.NewReader(voteverifier.Artifacts.ProvingKey())
	if _, err := pk.ReadFrom(pkReader); err != nil {
		return nil, err
	}
	// calculate the witness with the assignment
	witness, err := frontend.NewWitness(assigment, ecc.BLS12_377.ScalarField())
	if err != nil {
		return nil, err
	}
	// generate the final proof
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return nil, err
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
