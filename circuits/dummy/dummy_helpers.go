package dummy

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

func Prove(placeholder, assigment frontend.Circuit, outer *big.Int, field *big.Int, persist bool) (constraint.ConstraintSystem, witness.Witness, groth16.Proof, groth16.VerifyingKey, error) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, placeholder)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("compile error: %w", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("setup error: %w", err)
	}
	fullWitness, err := frontend.NewWitness(assigment, field)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("full witness error: %w", err)
	}
	proof, err := groth16.Prove(ccs, pk, fullWitness, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("proof error: %w", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("pub witness error: %w", err)
	}
	if err = groth16.Verify(proof, vk, publicWitness, stdgroth16.GetNativeVerifierOptions(outer, field)); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("verify error: %w", err)
	}
	/*
			TODO: uncomment this block when the LocalInputsForTest function is fixed
		if persist {
			// persist the dummy verification key
			if err := circuits.StoreVerificationKey(vk, "dummy"); err != nil {
				log.Printf("error storing dummy vk: %v", err)
			}
			// persist the dummy proof
			if err := circuits.StoreProof(proof, "dummy"); err != nil {
				log.Printf("error storing dummy proof: %v", err)
			}
			// persist the dummy public witness
			log.Println("storing dummy public witness")
			if err := circuits.StoreWitness(fullWitness, "dummy"); err != nil {
				log.Printf("error storing dummy public witness: %v", err)
			}
		}
	*/
	return ccs, publicWitness, proof, vk, nil
}
