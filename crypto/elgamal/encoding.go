package elgamal

import (
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
)

// MarshalJSON serializes the Ballot to JSON.
func (z *Ballot) MarshalJSON() ([]byte, error) {
	// Prepare an array of raw JSON messages for each ciphertext.
	rawCts := make([]json.RawMessage, len(z.Ciphertexts))
	for i, ct := range z.Ciphertexts {
		ctBytes, err := json.Marshal(ct)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ciphertext[%d]: %w", i, err)
		}
		rawCts[i] = ctBytes
	}
	// Build a temporary struct that holds the curve type and ciphertexts.
	tmp := struct {
		CurveType   string            `json:"curveType"`
		Ciphertexts []json.RawMessage `json:"ciphertexts"`
	}{
		CurveType:   z.CurveType,
		Ciphertexts: rawCts,
	}
	return json.Marshal(tmp)
}

// UnmarshalJSON deserializes the Ballot from JSON.
func (z *Ballot) UnmarshalJSON(data []byte) error {
	// Define a temporary container to hold the raw fields.
	var tmp struct {
		CurveType   string            `json:"curveType"`
		Ciphertexts []json.RawMessage `json:"ciphertexts"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("failed to unmarshal ballot container: %w", err)
	}
	z.CurveType = tmp.CurveType

	if len(tmp.Ciphertexts) != circuits.FieldsPerBallot {
		return fmt.Errorf("expected %d ciphertexts, got %d", circuits.FieldsPerBallot, len(tmp.Ciphertexts))
	}

	// Create a new array for the ciphertexts.
	var cts [circuits.FieldsPerBallot]*Ciphertext
	for i, raw := range tmp.Ciphertexts {
		ct := NewCiphertext(curves.New(z.CurveType))
		if err := ct.UnmarshalJSON(raw); err != nil {
			return fmt.Errorf("failed to unmarshal ciphertext[%d]: %w", i, err)
		}
		cts[i] = ct
	}
	z.Ciphertexts = cts
	return nil
}

// MarshalJSON serializes the Ciphertext to JSON.
func (z *Ciphertext) MarshalJSON() ([]byte, error) {
	// Marshal each point using its own JSON implementation.
	c1Bytes, err := json.Marshal(z.C1)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal c1: %w", err)
	}
	c2Bytes, err := json.Marshal(z.C2)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal c2: %w", err)
	}
	// Package the two into a temporary struct.
	tmp := struct {
		C1 json.RawMessage `json:"c1"`
		C2 json.RawMessage `json:"c2"`
	}{
		C1: c1Bytes,
		C2: c2Bytes,
	}
	return json.Marshal(tmp)
}

// UnmarshalJSON deserializes the Ciphertext from JSON.
func (z *Ciphertext) UnmarshalJSON(data []byte) error {
	// Define a temporary container matching the expected JSON.
	var tmp struct {
		C1 json.RawMessage `json:"c1"`
		C2 json.RawMessage `json:"c2"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("failed to unmarshal ciphertext container: %w", err)
	}
	// Here we assume that z.C1 and z.C2 have been allocated by the caller.
	// (Typically, the Ballot's UnmarshalJSON will create new Ciphertext objects
	// with allocated points using the proper curve.)
	if err := json.Unmarshal(tmp.C1, z.C1); err != nil {
		return fmt.Errorf("failed to unmarshal c1: %w", err)
	}
	if err := json.Unmarshal(tmp.C2, z.C2); err != nil {
		return fmt.Errorf("failed to unmarshal c2: %w", err)
	}
	return nil
}

// MarshalCBOR serializes the Ballot to CBOR.
func (z *Ballot) MarshalCBOR() ([]byte, error) {
	// Prepare an array of raw CBOR messages for the ciphertexts.
	rawCts := make([]cbor.RawMessage, len(z.Ciphertexts))
	for i, ct := range z.Ciphertexts {
		raw, err := ct.MarshalCBOR()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ciphertext[%d]: %w", i, err)
		}
		rawCts[i] = raw
	}
	// Create a temporary structure that matches the on-wire format.
	tmp := struct {
		CurveType   string            `cbor:"curveType"`
		Ciphertexts []cbor.RawMessage `cbor:"ciphertexts"`
	}{
		CurveType:   z.CurveType,
		Ciphertexts: rawCts,
	}
	return cbor.Marshal(tmp)
}

// UnmarshalCBOR deserializes the Ballot from CBOR.
func (z *Ballot) UnmarshalCBOR(buf []byte) error {
	// Use a temporary structure that mirrors the on‐wire representation.
	var tmp struct {
		CurveType   string            `cbor:"curveType"`
		Ciphertexts []cbor.RawMessage `cbor:"ciphertexts"`
	}
	if err := cbor.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	z.CurveType = tmp.CurveType

	if len(tmp.Ciphertexts) != circuits.FieldsPerBallot {
		return fmt.Errorf("expected %d ciphertexts, got %d", circuits.FieldsPerBallot, len(tmp.Ciphertexts))
	}

	z.Ciphertexts = [circuits.FieldsPerBallot]*Ciphertext{}
	for i, raw := range tmp.Ciphertexts {
		// Create a new ciphertext using the curve type.
		ct := NewCiphertext(curves.New(z.CurveType))
		if err := ct.UnmarshalCBOR(raw); err != nil {
			return fmt.Errorf("failed to unmarshal ciphertext[%d]: %w", i, err)
		}
		z.Ciphertexts[i] = ct
	}
	return nil
}

// MarshalCBOR serializes the Ciphertext to CBOR.
func (z *Ciphertext) MarshalCBOR() ([]byte, error) {
	// Marshal each point individually.
	c1Bytes, err := z.C1.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal c1: %w", err)
	}
	c2Bytes, err := z.C2.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal c2: %w", err)
	}
	// Package them into a temporary struct.
	tmp := struct {
		C1 cbor.RawMessage `cbor:"c1"`
		C2 cbor.RawMessage `cbor:"c2"`
	}{
		C1: c1Bytes,
		C2: c2Bytes,
	}
	return cbor.Marshal(tmp)
}

// UnmarshalCBOR deserializes the Ciphertext from CBOR.
func (z *Ciphertext) UnmarshalCBOR(buf []byte) error {
	// Use a temporary struct to extract the raw CBOR for each point.
	var tmp struct {
		C1 cbor.RawMessage `cbor:"c1"`
		C2 cbor.RawMessage `cbor:"c2"`
	}
	if err := cbor.Unmarshal(buf, &tmp); err != nil {
		return fmt.Errorf("failed to unmarshal ciphertext container: %w", err)
	}
	// At this point, we assume that z.C1 and z.C2 are already allocated.
	if err := z.C1.UnmarshalCBOR(tmp.C1); err != nil {
		return fmt.Errorf("failed to unmarshal c1: %w", err)
	}
	if err := z.C2.UnmarshalCBOR(tmp.C2); err != nil {
		return fmt.Errorf("failed to unmarshal c2: %w", err)
	}
	return nil
}
