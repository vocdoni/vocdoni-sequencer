package circuits

import "github.com/vocdoni/circom2gnark/parser"

// BallotProofNPubInputs is the number of public inputs for the ballot proof
// circom circuit.
const BallotProofNPubInputs = 1

// Circom2GnarkProof function is a wrapper to convert a circom proof to a gnark
// proof, it receives the circom proof and the public signals as strings, as
// snarkjs returns them. Then, it parses the inputs to the gnark format and
// transforms the proof to the gnark recursion format.
func Circom2GnarkProof(vkey []byte, circomProof, pubSignals string) (*parser.GnarkRecursionProof, error) {
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
