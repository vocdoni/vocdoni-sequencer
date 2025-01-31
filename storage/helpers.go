package storage

import (
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Artifact encoding/decoding
func encodeArtifact(a any) ([]byte, error) {
	encOpts := cbor.CoreDetEncOptions()
	em, err := encOpts.EncMode()
	if err != nil {
		return nil, fmt.Errorf("encode artifact: %w", err)
	}
	return em.Marshal(a)
}

func decodeArtifact(data []byte, out any) error {
	return cbor.Unmarshal(data, out)
}

func encodeReservation(r *reservationRecord) ([]byte, error) {
	return encodeArtifact(r)
}

func decodeReservation(data []byte) (*reservationRecord, error) {
	var r reservationRecord
	if err := decodeArtifact(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func hashKey(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:maxKeySize]
}
