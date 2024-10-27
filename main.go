package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/vocdoni/elGamal-sandbox/ecc"
	"github.com/vocdoni/elGamal-sandbox/ecc/curves"
)

type EncryptedVote struct {
	C1 []byte `json:"c1"`
	C2 []byte `json:"c2"`
}

type VoteData struct {
	Curve          string                   `json:"curve"`
	Participants   map[int]*ParticipantData `json:"participants"`
	ExpectedSum    string                   `json:"expectedSum"`
	VoteCount      uint64                   `json:"voteCount"`
	EncryptedVotes []EncryptedVote          `json:"encryptedVotes"`
}

type ParticipantData struct {
	ID           int      `json:"id"`
	PrivateShare string   `json:"privateShare"`
	PublicKey    []byte   `json:"publicKey"`
	PublicCoeffs [][]byte `json:"publicCoeffs"`
}

func main() {
	// Parameters
	maxValue := 5    // Number of candidates (e.g., 0 to 4)
	numVoters := 100 // Number of voters
	curve := ""
	filepath := ""

	flag.IntVar(&maxValue, "maxValue", 5, "Number of candidates (e.g., 0 to 4)")
	flag.IntVar(&numVoters, "numVoters", 100, "Number of voters")
	flag.BoolVar(&useBabyStepGiantStep, "useBabyStepGiantStep", true, "Use Baby-step Giant-step algorithm for discrete logarithm")
	flag.StringVar(&curve, "curve", curves.CurveTypeBN254, "Curve type: bjj_gnark or bjj_iden3 (BabyJubJub) or bn254 (BN254)")
	flag.StringVar(&filepath, "filepath", "", "File path to store or read the vote data. If specified, the program will read or write the vote data to the file.")
	flag.Parse()

	curvePoint, err := curves.New(curve)
	if err != nil {
		log.Fatalf("Failed to create curve point: %v", err)
	}

	var participants map[int]*Participant
	var expectedSum *big.Int
	var encryptedVotes []EncryptedVote
	var aggC1, aggC2 ecc.Point

	// Check if filepath is specified
	if filepath != "" {
		// Check if file exists
		if _, err := os.Stat(filepath); os.IsNotExist(err) {
			// File does not exist, create it and save data
			log.Printf("File %s does not exist. Creating new data...", filepath)
			participants, expectedSum, encryptedVotes, aggC1, aggC2 = generateData(curvePoint, maxValue, numVoters)
			saveData(filepath, curve, participants, expectedSum, encryptedVotes)
		} else {
			// File exists, load data
			log.Printf("Loading data from file %s...", filepath)
			participants, expectedSum, encryptedVotes, aggC1, aggC2 = loadData(filepath, curvePoint)

			// Check if we need to generate more votes
			if uint64(len(encryptedVotes)) < uint64(numVoters) {
				missingVotes := numVoters - len(encryptedVotes)
				log.Printf("Generating %d additional votes...", missingVotes)
				newExpectedSum, newEncryptedVotes, newAggC1, newAggC2 := generateVotes(curvePoint, participants[1].PublicKey, maxValue, missingVotes)
				expectedSum.Add(expectedSum, newExpectedSum)
				encryptedVotes = append(encryptedVotes, newEncryptedVotes...)
				aggC1.Add(aggC1, newAggC1)
				aggC2.Add(aggC2, newAggC2)
				saveData(filepath, curve, participants, expectedSum, encryptedVotes)
			}
		}
	} else {
		// No filepath specified, generate data without saving
		participants, expectedSum, _, aggC1, aggC2 = generateData(curvePoint, maxValue, numVoters)
	}

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
	decryptedSum, err := CombinePartialDecryptions(aggC2, partialDecryptions, participantSubset)
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

func generateData(curvePoint ecc.Point, maxValue, numVoters int) (map[int]*Participant, *big.Int, []EncryptedVote, ecc.Point, ecc.Point) {
	// Timing the DKG phase
	dkgStart := time.Now()

	// Threshold parameters
	threshold := 3
	participantIDs := []int{1, 2, 3, 4, 5}

	// Initialize participants
	participants := make(map[int]*Participant)
	for _, id := range participantIDs {
		participants[id] = NewParticipant(id, threshold, participantIDs, curvePoint)
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
					os.Exit(1)
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
	var encryptedVotes []EncryptedVote
	var mu sync.Mutex // Mutex to protect access to encryptedVotes

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
		go func(voteValue *big.Int) {
			defer func() {
				wg.Done()
				<-sem
			}()
			c1, c2, err := Encrypt(voteValue, participants[1].PublicKey)
			if err != nil {
				log.Fatalf("Encryption failed: %v", err)
			}
			// Aggregate ciphertexts
			aggC1.SafeAdd(aggC1, c1)
			aggC2.SafeAdd(aggC2, c2)

			// Store encrypted vote with mutex protection
			mu.Lock()
			encryptedVotes = append(encryptedVotes, EncryptedVote{
				C1: c1.Marshal(),
				C2: c2.Marshal(),
			})
			mu.Unlock()
		}(voteValue)
	}
	wg.Wait()

	votingDuration := time.Since(votingStart)
	log.Printf("Voting Phase Duration: %s", votingDuration)

	return participants, expectedSum, encryptedVotes, aggC1, aggC2
}

func generateVotes(curvePoint ecc.Point, publicKey ecc.Point, maxValue int, numVotes int) (*big.Int, []EncryptedVote, ecc.Point, ecc.Point) {
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
	log.Printf("Simulating %d votes...", numVotes)
	var encryptedVotes []EncryptedVote
	var mu sync.Mutex // Mutex to protect access to encryptedVotes

	wg := sync.WaitGroup{}
	sem := make(chan struct{}, 100)
	for i := 0; i < numVotes; i++ {
		voteValue, err := rand.Int(rand.Reader, big.NewInt(int64(maxValue)))
		if err != nil {
			log.Fatalf("Failed to generate random vote: %v", err)
		}
		expectedSum.Add(expectedSum, voteValue)
		wg.Add(1)
		sem <- struct{}{}
		go func(voteValue *big.Int) {
			defer func() {
				wg.Done()
				<-sem
			}()
			c1, c2, err := Encrypt(voteValue, publicKey)
			if err != nil {
				log.Fatalf("Encryption failed: %v", err)
			}
			// Aggregate ciphertexts
			aggC1.SafeAdd(aggC1, c1)
			aggC2.SafeAdd(aggC2, c2)

			// Store encrypted vote with mutex protection
			mu.Lock()
			encryptedVotes = append(encryptedVotes, EncryptedVote{
				C1: c1.Marshal(),
				C2: c2.Marshal(),
			})
			mu.Unlock()
		}(voteValue)
	}
	wg.Wait()

	votingDuration := time.Since(votingStart)
	log.Printf("Additional Voting Phase Duration: %s", votingDuration)

	return expectedSum, encryptedVotes, aggC1, aggC2
}

func saveData(filepath, curve string, participants map[int]*Participant, expectedSum *big.Int, encryptedVotes []EncryptedVote) {
	voteData := VoteData{
		Curve:          curve,
		Participants:   make(map[int]*ParticipantData),
		ExpectedSum:    expectedSum.String(),
		VoteCount:      uint64(len(encryptedVotes)),
		EncryptedVotes: encryptedVotes,
	}

	// Serialize participants
	for id, p := range participants {
		pData := &ParticipantData{
			ID:           p.ID,
			PrivateShare: p.PrivateShare.String(),
			PublicKey:    p.PublicKey.Marshal(),
			PublicCoeffs: [][]byte{},
		}
		for _, coeff := range p.PublicCoeffs {
			pData.PublicCoeffs = append(pData.PublicCoeffs, coeff.Marshal())
		}
		voteData.Participants[id] = pData
	}

	dataBytes, err := json.MarshalIndent(voteData, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal vote data: %v", err)
	}

	err = os.WriteFile(filepath, dataBytes, 0644)
	if err != nil {
		log.Fatalf("Failed to write vote data to file: %v", err)
	}

	log.Printf("Data saved to %s", filepath)
}

func loadData(filepath string, curvePoint ecc.Point) (map[int]*Participant, *big.Int, []EncryptedVote, ecc.Point, ecc.Point) {
	dataBytes, err := os.ReadFile(filepath)
	if err != nil {
		log.Fatalf("Failed to read vote data from file: %v", err)
	}

	var voteData VoteData
	err = json.Unmarshal(dataBytes, &voteData)
	if err != nil {
		log.Fatalf("Failed to unmarshal vote data: %v", err)
	}

	expectedSum := new(big.Int)
	if _, ok := expectedSum.SetString(voteData.ExpectedSum, 10); !ok {
		log.Fatalf("Failed to parse expected sum: %s", voteData.ExpectedSum)
	}

	participants := make(map[int]*Participant)
	for id, pData := range voteData.Participants {
		p := &Participant{
			ID:           pData.ID,
			PrivateShare: new(big.Int),
			PublicKey:    curvePoint.New(),
			CurvePoint:   curvePoint,
			PublicCoeffs: []ecc.Point{},
		}
		if _, ok := p.PrivateShare.SetString(pData.PrivateShare, 10); !ok {
			log.Fatalf("Failed to parse private share: %s", pData.PrivateShare)
		}
		if err := p.PublicKey.Unmarshal(pData.PublicKey); err != nil {
			log.Fatalf("Failed to unmarshal public key: %v", err)
		}

		// Deserialize public coefficients
		for _, coeffBytes := range pData.PublicCoeffs {
			coeffPoint := curvePoint.New()
			if err := coeffPoint.Unmarshal(coeffBytes); err != nil {
				log.Fatalf("Failed to unmarshal public coefficient: %v", err)
			}
			p.PublicCoeffs = append(p.PublicCoeffs, coeffPoint)
		}

		participants[id] = p
	}

	encryptedVotes := voteData.EncryptedVotes

	// Reconstruct aggC1 and aggC2
	aggC1 := curvePoint.New()
	aggC1.SetZero()
	aggC2 := curvePoint.New()
	aggC2.SetZero()

	for _, ev := range encryptedVotes {
		c1 := curvePoint.New()
		if err := c1.Unmarshal(ev.C1); err != nil {
			log.Fatalf("Failed to unmarshal c1: %v", err)
		}
		c2 := curvePoint.New()
		if err := c2.Unmarshal(ev.C2); err != nil {
			log.Fatalf("Failed to unmarshal c2: %v", err)
		}
		aggC1.Add(aggC1, c1)
		aggC2.Add(aggC2, c2)
	}

	return participants, expectedSum, encryptedVotes, aggC1, aggC2
}
