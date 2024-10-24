package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
)

// Participant represents a participant in the DKG protocol.
type Participant struct {
	ID             int
	Threshold      int
	Participants   []int
	SecretCoeffs   []*big.Int
	PublicCoeffs   []*G1
	SecretShares   map[int]*big.Int
	ReceivedShares map[int]*big.Int
	PrivateShare   *big.Int
	PublicKey      *G1
}

// NewParticipant initializes a new participant.
func NewParticipant(id int, threshold int, participants []int) *Participant {
	return &Participant{
		ID:             id,
		Threshold:      threshold,
		Participants:   participants,
		SecretCoeffs:   []*big.Int{},
		PublicCoeffs:   []*G1{},
		SecretShares:   make(map[int]*big.Int),
		ReceivedShares: make(map[int]*big.Int),
		PrivateShare:   new(big.Int),
		PublicKey:      &G1{},
	}
}

func (p *Participant) GenerateSecretPolynomial() {
	degree := p.Threshold - 1

	// Generate random coefficients.
	for i := 0; i <= degree; i++ {
		coeff, err := rand.Int(rand.Reader, Order)
		if err != nil {
			panic(err)
		}
		p.SecretCoeffs = append(p.SecretCoeffs, coeff)

		// Compute commitment G1 generator * coeff.
		commitment := &G1{}
		commitment.ScalarBaseMult(coeff)
		p.PublicCoeffs = append(p.PublicCoeffs, commitment)

		// Log the secret coefficient and commitment
		//log.Printf("Participant %d: SecretCoeff[%d] = %s", p.ID, i, coeff.String())
		//log.Printf("Participant %d: PublicCoeff[%d] = %s", p.ID, i, commitment.String())
	}
}

// ComputeShares computes shares to send to other participants.
func (p *Participant) ComputeShares() {
	for _, pid := range p.Participants {
		// Evaluate the polynomial at x = pid.
		share := p.evaluatePolynomial(big.NewInt(int64(pid)))
		p.SecretShares[pid] = share
		// Log the computed share
		log.Printf("Participant %d: Share for Participant %d = %s", p.ID, pid, share.String())
	}
}

// evaluatePolynomial evaluates the secret polynomial at a given x.
func (p *Participant) evaluatePolynomial(x *big.Int) *big.Int {
	result := big.NewInt(0)
	xPower := big.NewInt(1)

	for _, coeff := range p.SecretCoeffs {
		term := new(big.Int).Mul(coeff, xPower)
		term.Mod(term, Order)
		result.Add(result, term)
		result.Mod(result, Order)

		xPower.Mul(xPower, x)
		xPower.Mod(xPower, Order)
	}
	return result
}

// ReceiveShare receives a share from another participant.
func (p *Participant) ReceiveShare(fromID int, share *big.Int, publicCoeffs []*G1) error {
	// Verify the share using the commitments.
	if !p.verifyShare(share, publicCoeffs) {
		return fmt.Errorf("invalid share from participant %d", fromID)
	}
	p.ReceivedShares[fromID] = share
	return nil
}

// verifyShare verifies a received share using the commitments.
func (p *Participant) verifyShare(share *big.Int, publicCoeffs []*G1) bool {
	// Compute lhs = G1 * share
	lhs := &G1{}
	lhs.ScalarBaseMult(share)

	// Compute rhs = sum_{i} publicCoeffs[i] * x^{i}
	rhs := &G1{}
	x := big.NewInt(int64(p.ID))
	xPower := big.NewInt(1)

	for _, coeffCommitment := range publicCoeffs {
		term := &G1{}
		term.ScalarMult(coeffCommitment, xPower)
		rhs.Add(rhs, term)

		xPower.Mul(xPower, x)
		xPower.Mod(xPower, Order)
	}

	return lhs.Equal(rhs)
}

// AggregateShares aggregates the received shares to compute the private share.
func (p *Participant) AggregateShares() {
	p.PrivateShare.Set(p.SecretShares[p.ID])
	for _, share := range p.ReceivedShares {
		p.PrivateShare.Add(p.PrivateShare, share)
		p.PrivateShare.Mod(p.PrivateShare, Order)
	}
	// Log the aggregated private share
	log.Printf("Participant %d: PrivateShare = %s", p.ID, p.PrivateShare.String())
}

// AggregatePublicKey aggregates the public commitments to compute the public key.
func (p *Participant) AggregatePublicKey(allPublicCoeffs map[int][]*G1) {
	pk := &G1{}
	for _, coeffs := range allPublicCoeffs {
		pk.Add(pk, coeffs[0]) // Only the constant term is needed
	}
	p.PublicKey = pk
	// Log the aggregated public key
	log.Printf("Participant %d: PublicKey = %s", p.ID, p.PublicKey.String())
}
