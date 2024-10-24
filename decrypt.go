package main

import (
	"fmt"
	"log"
	"math/big"
)

const (
	discreteLogMaxMessage = 1000000
	numWorkersDiscreteLog = 8
)

// ComputePartialDecryption computes the partial decryption using the participant's private share.
func (p *Participant) ComputePartialDecryption(c1 *G1) *G1 {
	// Compute s_i = privateShare * C1.
	si := &G1{}
	si.ScalarMult(c1, p.PrivateShare)
	// Log the partial decryption
	log.Printf("Participant %d: Partial Decryption = %s", p.ID, si.String())
	return si
}

// CombinePartialDecryptions combines partial decryptions to recover the message.
func CombinePartialDecryptions(c2 *G1, partialDecryptions map[int]*G1, participants []int) (*big.Int, error) {
	// Compute Lagrange coefficients.
	lagrangeCoeffs := computeLagrangeCoefficients(participants)
	log.Printf("Lagrange Coefficients: %v", lagrangeCoeffs)

	// Sum up the partial decryptions weighted by Lagrange coefficients.
	s := &G1{}
	for _, id := range participants {
		pd := partialDecryptions[id]
		lambda := lagrangeCoeffs[id]
		term := &G1{}
		term.ScalarMult(pd, lambda)
		s.Add(s, term)
		// Log the weighted partial decryption
		log.Printf("Participant %d: Weighted Partial Decryption = %s", id, term.String())
	}

	// Compute M = C2 - s.
	s.Neg(s)
	m := &G1{}
	m.Add(c2, s)
	log.Printf("Computed M = %s", m.String())

	// Recover message scalar from point M.
	// Since M = message * G, find scalar 'message' such that M = message * G.
	// This is the discrete logarithm problem.

	// Perform a parallel brute-force search.
	type result struct {
		messageScalar *big.Int
		found         bool
	}

	results := make(chan result, numWorkersDiscreteLog)
	done := make(chan struct{})
	defer close(done)

	// Worker function
	worker := func(start, end int) {
		testPoint := &G1{}
		for i := start; i <= end; i++ {
			messageScalar := big.NewInt(int64(i))
			testPoint.ScalarBaseMult(messageScalar)
			if testPoint.Equal(m) {
				select {
				case results <- result{messageScalar, true}:
				case <-done:
				}
				return
			}
		}
		results <- result{nil, false}
	}

	// Start workers
	step := discreteLogMaxMessage / numWorkersDiscreteLog
	for i := 0; i < numWorkersDiscreteLog; i++ {
		start := i * step
		end := start + step - 1
		if i == numWorkersDiscreteLog-1 {
			end = discreteLogMaxMessage
		}
		go worker(start, end)
	}

	// Collect results
	for i := 0; i < numWorkersDiscreteLog; i++ {
		res := <-results
		if res.found {
			log.Printf("Decrypted Message Found: %s", res.messageScalar.String())
			return res.messageScalar, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt message, discrete logarithm problem unsolved")
}

// computeLagrangeCoefficients computes Lagrange coefficients for given participant IDs.
func computeLagrangeCoefficients(participants []int) map[int]*big.Int {
	coeffs := make(map[int]*big.Int)
	mod := Order
	for _, i := range participants {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)
		for _, j := range participants {
			if i != j {
				// numerator *= -j mod mod
				tempNum := big.NewInt(int64(-j))
				tempNum.Mod(tempNum, mod)
				numerator.Mul(numerator, tempNum)
				numerator.Mod(numerator, mod)

				// denominator *= (i - j) mod mod
				tempDen := big.NewInt(int64(i - j))
				if tempDen.Sign() < 0 {
					tempDen.Add(tempDen, mod)
				}
				tempDen.Mod(tempDen, mod)
				denominator.Mul(denominator, tempDen)
				denominator.Mod(denominator, mod)
			}
		}
		denominatorInv := new(big.Int).ModInverse(denominator, mod)
		if denominatorInv == nil {
			log.Fatalf("Modular inverse does not exist for denominator %s modulo %s", denominator.String(), mod.String())
		}
		coeff := new(big.Int).Mul(numerator, denominatorInv)
		coeff.Mod(coeff, mod)
		coeffs[i] = coeff
	}
	return coeffs
}
