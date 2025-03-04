package processor

import (
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
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

// startBallotProcessor method starts the vote processor. It will process ballots in the
// background. It iterates over the ballots available in the storage and
// generates proofs of the validity of the ballots, storing them back in the
// storage. It will stop processing ballots when the context is cancelled.
func (p *Processor) startBallotProcessor() error {
	ticker := time.NewTicker(time.Second)

	go func() {
		defer ticker.Stop()
		for {
			// Try to fetch the next ballot.
			ballot, key, err := p.stg.NextBallot()
			if err != nil {
				// Log errors other than "no work".
				if err != storage.ErrNoMoreElements {
					log.Errorw(err, "failed to get next ballot")
				} else {
					// If no ballot is available, wait for the next tick or context cancellation.
					select {
					case <-ticker.C:
					case <-p.ctx.Done():
						return
					}
				}
				continue
			}

			log.Debugw("new ballot to process", "address", ballot.Address.String())
			startTime := time.Now()

			verifiedBallot, err := p.processBallot(ballot)
			if err != nil {
				log.Warnw("marking ballot as invalid", "address", ballot.Address.String(), "error", err.Error())
				continue
			}

			log.Debugw("ballot processed", "address", ballot.Address.String(), "took", time.Since(startTime).String())
			if err := p.stg.MarkBallotDone(key, verifiedBallot); err != nil {
				log.Errorw(err, "failed to mark ballot done")
			}
		}
	}()
	return nil
}

// processBallot method processes a ballot, generating a proof of its validity.
// It gets the process information from the storage, transforms it to the
// circuit types, and generates the proof using the gnark library. It returns
// the verified ballot with the proof.
func (p *Processor) processBallot(b *storage.Ballot) (*storage.VerifiedBallot, error) {
	// check if the ballot is valid
	if !b.Valid() {
		return nil, fmt.Errorf("invalid ballot")
	}
	// get the process metadata
	process, err := p.stg.Process(new(types.ProcessID).SetBytes(b.ProcessID))
	if err != nil {
		return nil, fmt.Errorf("failed to get process metadata: %w", err)
	}
	// transform to circuit types
	processID := crypto.BigToFF(circuits.BallotProofCurve.ScalarField(), b.ProcessID.BigInt().MathBigInt())
	root := arbo.BytesToBigInt(process.Census.CensusRoot)
	ballotMode := circuits.BallotModeToCircuit(*process.BallotMode)
	encryptionKey := circuits.EncryptionKeyToCircuit(*process.EncryptionKey)
	// calculate inputs hash
	hashInputs := []*big.Int{}
	hashInputs = append(hashInputs, processID)
	hashInputs = append(hashInputs, root)
	hashInputs = append(hashInputs, ballotMode.Serialize()...)
	hashInputs = append(hashInputs, encryptionKey.Serialize()...)
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

	// transform the inputs to big Ints
	address := b.Address.BigInt().MathBigInt()
	commitment := b.Commitment.BigInt().MathBigInt()
	nullifier := b.Nullifier.BigInt().MathBigInt()
	voterWeight := b.VoterWeight.BigInt().MathBigInt()

	// set the circuit assignment
	assignment := voteverifier.VerifyVoteCircuit{
		IsValid:    1,
		InputsHash: emulated.ValueOf[sw_bn254.ScalarField](inputHash),
		Vote: circuits.EmulatedVote[sw_bn254.ScalarField]{
			Address:    emulated.ValueOf[sw_bn254.ScalarField](address),
			Commitment: emulated.ValueOf[sw_bn254.ScalarField](commitment),
			Nullifier:  emulated.ValueOf[sw_bn254.ScalarField](nullifier),
			Ballot:     *b.EncryptedBallot.ToGnarkEmulatedBN254(),
		},
		UserWeight: emulated.ValueOf[sw_bn254.ScalarField](voterWeight),
		Process: circuits.Process[emulated.Element[sw_bn254.ScalarField]]{
			ID:            emulated.ValueOf[sw_bn254.ScalarField](processID),
			CensusRoot:    emulated.ValueOf[sw_bn254.ScalarField](root),
			EncryptionKey: encryptionKey.BigIntsToEmulatedElementBN254(),
			BallotMode:    ballotMode.BigIntsToEmulatedElementBN254(),
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

	// calculate the witness with the assignment
	witness, err := frontend.NewWitness(assignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}
	// generate the final proof
	proof, err := groth16.Prove(p.voteCcs, p.voteProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	return &storage.VerifiedBallot{
		ProcessID:       b.ProcessID,
		VoterWeight:     voterWeight,
		Nullifier:       nullifier,
		Commitment:      commitment,
		EncryptedBallot: b.EncryptedBallot,
		Address:         address,
		Proof:           proof,
		InputsHash:      inputHash,
	}, nil
}
