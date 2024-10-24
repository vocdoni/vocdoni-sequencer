package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"time"
)

func main() {
	// Parameters
	maxValue := 5    // Number of candidates (e.g., 0 to 4)
	numVoters := 100 // Number of voters

	flag.IntVar(&maxValue, "maxValue", 5, "Number of candidates (e.g., 0 to 4)")
	flag.IntVar(&numVoters, "numVoters", 100, "Number of voters")
	flag.Parse()

	// Timing the DKG phase
	dkgStart := time.Now()

	// Threshold parameters
	threshold := 3
	participantIDs := []int{1, 2, 3, 4, 5}

	// Initialize participants
	participants := make(map[int]*Participant)
	for _, id := range participantIDs {
		participants[id] = NewParticipant(id, threshold, participantIDs)
		participants[id].GenerateSecretPolynomial()
	}

	// Exchange commitments and shares
	allPublicCoeffs := make(map[int][]*G1)
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

	// Generate random votes
	votes := make([]*big.Int, numVoters)
	for i := 0; i < numVoters; i++ {
		voteValue, err := rand.Int(rand.Reader, big.NewInt(int64(maxValue)))
		if err != nil {
			log.Fatalf("Failed to generate random vote: %v", err)
		}
		votes[i] = voteValue
	}

	// Encrypt votes
	encryptedVotes := make([][2]*G1, numVoters)
	for i, vote := range votes {
		c1, c2, err := Encrypt(vote, participants[1].PublicKey)
		if err != nil {
			log.Fatalf("Encryption failed for vote %d: %v", i, err)
		}
		encryptedVotes[i] = [2]*G1{c1, c2}
	}

	votingDuration := time.Since(votingStart)
	log.Printf("Voting Phase Duration: %s", votingDuration)

	// Aggregation of encrypted votes
	aggregationStart := time.Now()

	// Initialize aggC1 and aggC2 to the identity element (point at infinity)
	aggC1 := &G1{}
	aggC1.SetZero()

	aggC2 := &G1{}
	aggC2.SetZero()

	// Aggregate ciphertexts
	for _, encVote := range encryptedVotes {
		aggC1.Add(aggC1, encVote[0])
		aggC2.Add(aggC2, encVote[1])
	}

	aggregationDuration := time.Since(aggregationStart)
	log.Printf("Aggregation Phase Duration: %s", aggregationDuration)

	// Decryption
	decryptionStart := time.Now()

	// Participants compute partial decryptions
	partialDecryptions := make(map[int]*G1)
	participantSubset := []int{1, 2, 3} // Using threshold number of participants
	for _, id := range participantSubset {
		p := participants[id]
		pd := p.ComputePartialDecryption(aggC1)
		partialDecryptions[id] = pd
	}

	// Combine partial decryptions to recover the sum of votes
	decryptedSum, err := CombinePartialDecryptions(aggC2, partialDecryptions, participantSubset)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	} else {
		log.Printf("Decrypted sum of votes: %s", decryptedSum.String())
	}

	decryptionDuration := time.Since(decryptionStart)
	log.Printf("Decryption Phase Duration: %s", decryptionDuration)

	// Verify the sum
	// Calculate the expected sum
	expectedSum := big.NewInt(0)
	for _, vote := range votes {
		expectedSum.Add(expectedSum, vote)
	}

	if decryptedSum.Cmp(expectedSum) == 0 {
		log.Printf("Success: Decrypted sum matches the expected sum.")
	} else {
		log.Printf("Mismatch: Decrypted sum does not match the expected sum.")
		log.Printf("Expected sum: %s", expectedSum.String())
	}
}
