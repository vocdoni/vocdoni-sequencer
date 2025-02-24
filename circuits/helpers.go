package circuits

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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

func Groth16SolidityAssets(name string, c, w frontend.Circuit, field *big.Int) error {
	// compile the circuit
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, c)
	if err != nil {
		log.Println(1)
		return err
	}
	// generate witness
	witness, err := frontend.NewWitness(w, field)
	if err != nil {
		log.Println(2)
		return err
	}
	// get public witness
	pubWitness, err := witness.Public()
	if err != nil {
		log.Println(3)
		return err
	}
	// generate proving and verifying keys
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Println(4)
		return err
	}
	// generate proof
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Println(5)
		return err
	}
	// write proof into a buffer
	var buf bytes.Buffer
	_, err = proof.WriteRawTo(&buf)
	if err != nil {
		log.Println(6)
		return err
	}
	proofBytes := buf.Bytes()
	// compose the proof for solidity
	type SolidityProof struct {
		Ar  [2]*big.Int    `json:"Ar"`
		Bs  [2][2]*big.Int `json:"Bs"`
		Krs [2]*big.Int    `json:"Krs"`
	}
	p := SolidityProof{}
	// proof.Ar, proof.Bs, proof.Krs
	const fpSize = 4 * 8
	p.Ar[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	p.Ar[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	p.Bs[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	p.Bs[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	p.Bs[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	p.Bs[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	p.Krs[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	p.Krs[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])
	// write proof into a file
	prooffd, err := os.Create(fmt.Sprintf("%s_proof.json", name))
	if err != nil {
		log.Println(7)
		return err
	}
	defer prooffd.Close()
	bProof, err := json.Marshal(p)
	if err != nil {
		log.Println(8)
		return err
	}
	_, err = prooffd.Write(bProof)
	if err != nil {
		log.Println(9)
		return err
	}
	// generate solidity verifier
	solfd, err := os.Create(fmt.Sprintf("%s.sol", name))
	if err != nil {
		log.Println(10)
		return err
	}
	defer solfd.Close()
	// write verifier
	err = vk.ExportSolidity(solfd)
	if err != nil {
		log.Println(11)
		return err
	}
	// generate also the json of the public witness
	schema, err := frontend.NewSchema(w)
	if err != nil {
		log.Println(12)
		return err
	}
	jsonWitness, err := pubWitness.ToJSON(schema)
	if err != nil {
		log.Println(13)
		return err
	}
	pubWitnessJSONfd, err := os.Create(fmt.Sprintf("%s_witness.json", name))
	if err != nil {
		log.Println(14)
		return err
	}
	defer pubWitnessJSONfd.Close()
	_, err = pubWitnessJSONfd.Write(jsonWitness)
	if err != nil {
		log.Println(15)
		return err
	}
	return nil
}
