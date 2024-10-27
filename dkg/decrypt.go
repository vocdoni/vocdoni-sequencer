package dkg

import (
	"fmt"
	"log"
	"math"
	"math/big"

	"github.com/vocdoni/elGamal-sandbox/ecc"
)

const (
	// numWorkersDiscreteLogBruteForce is the number of workers for parallel brute-force search
	numWorkersDiscreteLogBruteForce = 10
)

// UseBabyStepGiantStep determines whether to use the Baby-Step Giant-Step algorithm for discrete logarithm.
var UseBabyStepGiantStep = true

// ComputePartialDecryption computes the partial decryption using the participant's private share.
func (p *Participant) ComputePartialDecryption(c1 ecc.Point) ecc.Point {
	// Compute s_i = privateShare * C1.
	si := c1.New()
	si.ScalarMult(c1, p.PrivateShare)
	// Log the partial decryption
	log.Printf("Participant %d: Partial Decryption = %s", p.ID, si.String())
	return si
}

// CombinePartialDecryptions combines partial decryptions to recover the message.
func CombinePartialDecryptions(c2 ecc.Point, partialDecryptions map[int]ecc.Point, participants []int, maxMessage uint64) (*big.Int, error) {
	// Compute Lagrange coefficients.
	lagrangeCoeffs := computeLagrangeCoefficients(participants, c2.Order())
	log.Printf("Lagrange Coefficients: %v", lagrangeCoeffs)

	// Sum up the partial decryptions weighted by Lagrange coefficients.
	s := c2.New()
	for _, id := range participants {
		pd := partialDecryptions[id]
		lambda := lagrangeCoeffs[id]
		term := s.New()
		term.ScalarMult(pd, lambda)
		s.Add(s, term)
		// Log the weighted partial decryption
		log.Printf("Participant %d: Weighted Partial Decryption = %s", id, term.String())
	}

	// Compute M = C2 - s.
	s.Neg(s)
	m := c2.New()
	m.Add(c2, s)
	log.Printf("Computed M = %s", m.String())

	// Recover message scalar from point M.
	// Since M = message * G, find scalar 'message' such that M = message * G.
	// This is the discrete logarithm problem.

	if UseBabyStepGiantStep {
		// Use Pollard's Kangaroo algorithm to solve the discrete logarithm problem.
		// This is a more efficient algorithm compared to brute-force search.
		// However it is not guaranteed to find the solution and may fail in some cases.
		log.Print("Using Baby-Step Giant-Step algorithm to solve the discrete logarithm problem...")
		messageScalar, err := babyStepGiantStep(m, maxMessage)
		if err != nil {
			log.Printf("Failed to decrypt message using Baby-Step Giant-Step algorithm: %v", err)
		} else {
			log.Printf("Decrypted Message Found: %s", messageScalar.String())
			return messageScalar, nil
		}
	}

	// Perform a parallel brute-force search.
	// Each worker searches for the message scalar in a range of values.
	// The search space is limited to discreteLogMaxMessage.
	// The number of workers is numWorkersDiscreteLog.
	// The first worker to find the message scalar returns it.
	// If no worker finds the message scalar, return an error.

	log.Print("Starting parallel brute-force search for message scalar...")

	type result struct {
		messageScalar *big.Int
		found         bool
	}

	results := make(chan result, numWorkersDiscreteLogBruteForce)
	done := make(chan struct{})
	defer close(done)

	// Worker function
	worker := func(start, end uint64) {
		testPoint := c2.New()
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
	step := maxMessage / numWorkersDiscreteLogBruteForce
	for i := 0; i < numWorkersDiscreteLogBruteForce; i++ {
		start := uint64(i) * step
		end := start + uint64(step-1)
		if i == numWorkersDiscreteLogBruteForce-1 {
			end = maxMessage
		}
		go worker(start, end)
	}

	// Collect results
	for i := 0; i < numWorkersDiscreteLogBruteForce; i++ {
		res := <-results
		if res.found {
			log.Printf("Decrypted Message Found: %s", res.messageScalar.String())
			return res.messageScalar, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt message, discrete logarithm problem unsolved")
}

// computeLagrangeCoefficients computes Lagrange coefficients for given participant IDs.
func computeLagrangeCoefficients(participants []int, mod *big.Int) map[int]*big.Int {
	coeffs := make(map[int]*big.Int)
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

// babyStepGiantStep computes the discrete logarithm using the Baby-Step Giant-Step algorithm.
func babyStepGiantStep(m ecc.Point, maxMessage uint64) (*big.Int, error) {
	mSqrt := uint64(math.Sqrt(float64(maxMessage))) + 1

	// Create a map for baby steps
	babySteps := make(map[string]uint64)
	G := m.New()
	G.SetGenerator()

	// Precompute baby steps
	babyStep := m.New()
	babyStep.SetZero()
	for j := uint64(0); j < mSqrt; j++ {
		key := babyStep.String()
		babySteps[key] = j
		babyStep.Add(babyStep, G)
	}

	// Compute the factor for giant steps: c = mSqrt * (-G)
	c := m.New()
	c.ScalarBaseMult(big.NewInt(int64(mSqrt)))
	c.Neg(c) // c = -mSqrt * G

	// Initialize the giant step
	giantStep := m.New()
	giantStep.Set(m)

	// Perform giant steps
	for i := uint64(0); i <= mSqrt; i++ {
		key := giantStep.String()
		if j, found := babySteps[key]; found {
			// x = i * mSqrt + j
			x := new(big.Int).SetUint64(i * mSqrt)
			x.Add(x, new(big.Int).SetUint64(j))
			return x, nil
		}
		giantStep.Add(giantStep, c)
	}

	return nil, fmt.Errorf("failed to compute discrete logarithm using Baby-Step Giant-Step algorithm")
}
