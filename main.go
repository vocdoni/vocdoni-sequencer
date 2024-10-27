package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vocdoni/elGamal-sandbox/dkg"
	"github.com/vocdoni/elGamal-sandbox/ecc"
	"github.com/vocdoni/elGamal-sandbox/ecc/curves"
)

func main() {
	// Parameters
	maxValue := 5    // Number of candidates (e.g., 0 to 4)
	numVoters := 100 // Number of voters
	curve := ""

	flag.IntVar(&maxValue, "maxValue", 5, "Number of candidates (e.g., 0 to 4)")
	flag.IntVar(&numVoters, "numVoters", 100, "Number of voters")
	flag.BoolVar(&dkg.UseBabyStepGiantStep, "useBabyStepGiantStep", true, "Use Baby-step Giant-step algorithm for discrete logarithm")
	flag.StringVar(&curve, "curve", curves.CurveTypeBN254, "Curve type: bjj_gnark or bjj_iden3 (BabyJubJub) or bn254 (BN254)")
	flag.Parse()

	curvePoint, err := curves.New(curve)
	if err != nil {
		log.Fatalf("Failed to create curve point: %v", err)
	}

	// Timing the DKG phase
	dkgStart := time.Now()

	// Threshold parameters
	threshold := 3
	participantIDs := []int{1, 2, 3, 4, 5}

	// Initialize participants
	participants := make(map[int]*dkg.Participant)
	for _, id := range participantIDs {
		participants[id] = dkg.NewParticipant(id, threshold, participantIDs, curvePoint)
		participants[id].GenerateSecretPolynomial()
	}

	// Exchange commitments and shares
	allPublicCoeffs := make(map[int][]ecc.Point)
	for id, p := range participants {
		allPublicCoeffs[id] = p.PublicCoeffs
	}

	// Each participant computes shares to send
	for _, p := range participants {
		p.ComputeShares()
	}

	// Participants exchange shares and verify
	for _, p := range participants {
		for id, otherP := range participants {
			if p.ID != id {
				share := otherP.SecretShares[p.ID]
				err := p.ReceiveShare(id, share, otherP.PublicCoeffs)
				if err != nil {
					fmt.Printf("Participant %d failed to verify share from %d: %v\n", p.ID, id, err)
					return
				}
			}
		}
	}

	// Each participant aggregates shares
	for _, p := range participants {
		p.AggregateShares()
	}

	// Compute aggregated public key
	for _, p := range participants {
		p.AggregatePublicKey(allPublicCoeffs)
	}

	dkgDuration := time.Since(dkgStart)
	log.Printf("DKG Phase Duration: %s", dkgDuration)

	// Simulate voting
	votingStart := time.Now()

	// expectedSum is the sum of all votes (plaintext)
	expectedSum := big.NewInt(0)

	// Initialize aggC1 and aggC2 to the identity element (point at infinity)
	aggC1 := curvePoint.New()
	aggC1.SetZero()

	aggC2 := curvePoint.New()
	aggC2.SetZero()

	// Generate random votes, encrypt and aggregate
	log.Printf("Simulating %d votes...", numVoters)
	var votesDone atomic.Uint32
	go func() {
		for {
			time.Sleep(10 * time.Second)
			votesDoneVal := votesDone.Load()
			if votesDoneVal == uint32(numVoters) {
				return
			}
			log.Printf("Votes done %d (%.2f%%)", votesDoneVal, float64(votesDoneVal)/float64(numVoters)*100)
		}
	}()
	wg := sync.WaitGroup{}
	sem := make(chan struct{}, 100)
	for i := 0; i < numVoters; i++ {
		voteValue, err := rand.Int(rand.Reader, big.NewInt(int64(maxValue)))
		if err != nil {
			log.Fatalf("Failed to generate random vote: %v", err)
		}
		expectedSum.Add(expectedSum, voteValue)
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			c1, c2, err := Encrypt(voteValue, participants[1].PublicKey)
			if err != nil {
				log.Fatalf("Encryption failed for vote %d: %v", i, err)
			}
			// Aggregate ciphertexts
			aggC1.SafeAdd(aggC1, c1)
			aggC2.SafeAdd(aggC2, c2)
			wg.Done()
			votesDone.Add(1)
			<-sem
		}()
	}
	wg.Wait()

	votingDuration := time.Since(votingStart)
	log.Printf("Voting Phase Duration: %s", votingDuration)

	// Decryption
	decryptionStart := time.Now()

	// Participants compute partial decryptions
	partialDecryptions := make(map[int]ecc.Point)
	participantSubset := []int{1, 2, 3} // Using threshold number of participants
	for _, id := range participantSubset {
		p := participants[id]
		pd := p.ComputePartialDecryption(aggC1)
		partialDecryptions[id] = pd
	}

	// Combine partial decryptions to recover the sum of votes
	decryptedSum, err := dkg.CombinePartialDecryptions(aggC2, partialDecryptions, participantSubset)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	} else {
		log.Printf("Decrypted sum of votes: %s", decryptedSum.String())
	}

	decryptionDuration := time.Since(decryptionStart)
	log.Printf("Decryption Phase Duration: %s", decryptionDuration)

	// Verify the sum
	if decryptedSum.Cmp(expectedSum) == 0 {
		log.Printf("Success: Decrypted sum matches the expected sum.")
	} else {
		log.Printf("Mismatch: Decrypted sum does not match the expected sum.")
		log.Printf("Expected sum: %s", expectedSum.String())
	}
}
