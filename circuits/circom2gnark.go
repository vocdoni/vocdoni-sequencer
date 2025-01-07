package circuits

import (
	"fmt"

	"github.com/vocdoni/circom2gnark/parser"
)

// BallotProofNPubInputs is the number of public inputs for the ballot proof
// circom circuit.
const BallotProofNPubInputs = 1

// Circom2GnarkProofForRecursion function is a wrapper to convert a circom
// proof to a gnark proof, it receives the circom proof and the public signals
// as strings, as snarkjs returns them. Then, it parses the inputs to the gnark
// format and transforms the proof to the gnark recursion format.
func Circom2GnarkProofForRecursion(vkey []byte, circomProof, pubSignals string) (*parser.GnarkRecursionProof, error) {
	// transform to gnark format
	gnarkProofData, err := parser.UnmarshalCircomProofJSON([]byte(circomProof))
	if err != nil {
		return nil, err
	}
	gnarkPubSignalsData, err := parser.UnmarshalCircomPublicSignalsJSON([]byte(pubSignals))
	if err != nil {
		return nil, err
	}
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return nil, err
	}
	proof, err := parser.ConvertCircomToGnarkRecursion(gnarkVKeyData, gnarkProofData, gnarkPubSignalsData, true)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

// VerifyAndConvertToRecursion function is a wrapper to circom2gnark that
// converts a circom proof to a gnark proof, verifies it and then converts it
// to a gnark recursion proof. It returns the resulting proof or an error.
func VerifyAndConvertToRecursion(vkey []byte, proof *parser.CircomProof, pubSignals []string) (
	*parser.GnarkRecursionProof, error,
) {
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return nil, err
	}
	gnarkProof, err := parser.ConvertCircomToGnark(gnarkVKeyData, proof, pubSignals)
	if err != nil {
		return nil, err
	}
	if ok, err := parser.VerifyProof(gnarkProof); !ok || err != nil {
		return nil, fmt.Errorf("proof verification failed: %v", err)
	}
	return parser.ConvertCircomToGnarkRecursion(gnarkVKeyData, proof, pubSignals, true)
}

// Circom2GnarkPlaceholder function is a wrapper to convert the circom ballot
// circuit to a gnark recursion placeholder, it returns the resulting
// placeholders for the recursion.
func Circom2GnarkPlaceholder(vkey []byte) (*parser.GnarkRecursionPlaceholders, error) {
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return nil, err
	}
	return parser.PlaceholdersForRecursion(gnarkVKeyData, BallotProofNPubInputs, true)
}
