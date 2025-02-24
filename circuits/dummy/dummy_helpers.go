package dummy

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
)

func Prove(placeholder, assignment frontend.Circuit, outer *big.Int, field *big.Int, persist bool, srs, srsLagrange kzg.SRS) (constraint.ConstraintSystem, witness.Witness, plonk.Proof, plonk.VerifyingKey, error) {
	ccs, pk, vk, err := CompileAndSetup(placeholder, field, srs, srsLagrange)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("init error: %w", err)
	}
	fullWitness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("full witness error: %w", err)
	}
	proof, err := plonk.Prove(ccs, pk, fullWitness, stdplonk.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("proof error: %w", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("pub witness error: %w", err)
	}
	if err = plonk.Verify(proof, vk, publicWitness, stdplonk.GetNativeVerifierOptions(outer, field)); err != nil {
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

func CompileAndSetup(placeholder frontend.Circuit, field *big.Int, srs, srsLagrange kzg.SRS) (constraint.ConstraintSystem, plonk.ProvingKey, plonk.VerifyingKey, error) {
	ccs, err := frontend.Compile(field, scs.NewBuilder, placeholder)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile error: %w", err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup error: %w", err)
	}
	return ccs, pk, vk, nil
}
