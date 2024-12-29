package voteverifier

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/ballotproof"
)

// GenInputsForTest returns the VoteVerifierTestResults, and
// the N assigments for a VerifyVoteCircuit. If
// processId is nil, it will be randomly generated. If something fails it
// returns an error.
func GenProofsForTest(processId []byte, nValidVoters int) (
	*VoteVerifierTestResults, []VerifyVoteCircuit, error,
) {
	// generate users accounts and census
	vvData := []VoterTestData{}
	for i := 0; i < nValidVoters; i++ {
		privKey, pubKey, address, err := ballotproof.GenECDSAaccountForTest()
		if err != nil {
			return nil, nil, err
		}
		vvData = append(vvData, VoterTestData{
			PrivKey: privKey,
			PubKey:  pubKey,
			Address: address,
		})
	}
	// generate vote verifier circuit and inputs
	return GenInputsForTest(vvData, processId)
}

func CompileAndSetup() (groth16.ProvingKey, groth16.VerifyingKey, error) {
	// compile vote verifier circuit
	r1cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, CircuitPlaceholder())
	if err != nil {
		return nil, nil, err
	}
	return groth16.Setup(r1cs)
}
