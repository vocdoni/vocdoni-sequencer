package circuits

import (
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
)

// FrontendError function is an in-circuit function to print an error message
// and an error trace, making the circuit fail.
func FrontendError(api frontend.API, msg string, trace error) {
	err := fmt.Errorf("%s", msg)
	if err != nil {
		err = fmt.Errorf("%w: %v", err, trace)
	}
	api.Println(err.Error())
	api.AssertIsEqual(1, 0)
}

// BigIntArrayToN pads the big.Int array to n elements, if needed,
// with zeros.
func BigIntArrayToN(arr []*big.Int, n int) []*big.Int {
	bigArr := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		if i < len(arr) {
			bigArr[i] = arr[i]
		} else {
			bigArr[i] = big.NewInt(0)
		}
	}
	return bigArr
}

// BigIntArrayToStringArray converts the big.Int array to a string array.
func BigIntArrayToStringArray(arr []*big.Int, n int) []string {
	strArr := []string{}
	for _, b := range BigIntArrayToN(arr, n) {
		strArr = append(strArr, b.String())
	}
	return strArr
}

// BigIntToMIMCHash transform the inputs hash to the field provided, if it is
// not done, the circuit will transform it during the witness calculation and
// the resulting hash will be different. Moreover, the input hash should be
// 32 bytes so if it is not, fill with zeros at the beginning of the bytes
// representation.
func BigIntToMIMCHash(input, base *big.Int) []byte {
	hash := ecc.BigToFF(base, input).Bytes()
	for len(hash) < SerializedFieldSize {
		hash = append([]byte{0}, hash...)
	}
	return hash
}

// StoreConstraintSystem stores the constraint system in a file.
func StoreConstraintSystem(cs constraint.ConstraintSystem, filepath string) error {
	// persist the constraint system
	csFd, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer csFd.Close()
	if _, err := cs.WriteTo(csFd); err != nil {
		return err
	}
	log.Printf("constraint system written to %s", filepath)
	return nil
}

// StoreVerificationKey stores the verification key in a file.
func StoreVerificationKey(vkey groth16.VerifyingKey, filepath string) error {
	fd, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer fd.Close()
	if _, err := vkey.WriteRawTo(fd); err != nil {
		return err
	}
	log.Printf("verification key written to %s", filepath)
	return nil
}

// StoreProof stores the proof in a file.
func StoreProof(proof groth16.Proof, filepath string) error {
	// persist the proof
	proofFd, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer proofFd.Close()
	if _, err := proof.WriteTo(proofFd); err != nil {
		return err
	}
	log.Printf("proof written to %s", filepath)
	return nil
}

// StoreWitness stores the witness in a file.
func StoreWitness(witness witness.Witness, filepath string) error {
	// persist the witness
	witnessFd, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer witnessFd.Close()
	bWitness, err := witness.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := witnessFd.Write(bWitness); err != nil {
		return err
	}
	return nil
}

// BoolToBigInt returns 1 when b is true or 0 otherwise
func BoolToBigInt(b bool) *big.Int {
	if b {
		return big.NewInt(1)
	}
	return big.NewInt(0)
}
