package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
)

// Artifact encoding/decoding
func encodeArtifact(a any) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(a); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeArtifact(data []byte, out any) error {
	return gob.NewDecoder(bytes.NewReader(data)).Decode(out)
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
