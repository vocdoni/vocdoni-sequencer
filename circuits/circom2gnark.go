package circuits

import (
	"fmt"

	"github.com/vocdoni/circom2gnark/parser"
)

// BallotProofNPubInputs is the number of public inputs for the ballot proof
// circom circuit.
const BallotProofNPubInputs = 1

// Circom2GnarkProof function is a wrapper to convert a circom proof to a gnark
// proof, it receives the circom proof and the public signals as strings, as
// snarkjs returns them. Then, it parses the inputs to the gnark format. It
// returns a parser.CircomProof and a list of public signals or an error.
func Circom2GnarkProof(circomProof, pubSignals string) (*parser.CircomProof, []string, error) {
	// transform to gnark format
	proofData, err := parser.UnmarshalCircomProofJSON([]byte(circomProof))
	if err != nil {
		return nil, nil, err
	}
	pubSignalsData, err := parser.UnmarshalCircomPublicSignalsJSON([]byte(pubSignals))
	if err != nil {
		return nil, nil, err
	}
	return proofData, pubSignalsData, nil
}

// Circom2GnarkProofForRecursion function is a wrapper to convert a circom
// proof to a gnark proof to be verified inside another gnark circuit. It
// receives the circom proof, the public signals and the verification key as
// strings, as snarkjs returns them. Then, it converts the proof, the public
// signals and the verification key to the gnark format and returns a gnark
// recursion proof or an error.
func Circom2GnarkProofForRecursion(vkey []byte, circomProof, pubSignals string) (*parser.GnarkRecursionProof, error) {
	// transform to gnark format
	gnarkProofData, gnarkPubSignalsData, err := Circom2GnarkProof(circomProof, pubSignals)
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
