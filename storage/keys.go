package storage

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"math/big"

	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

type encryptionKeys struct {
	PublicKeyX *big.Int
	PublicKeyY *big.Int
	PrivateKey *big.Int
}

// StoreEncryptionKeys stores the encryption keys for a process.
func (s *Storage) StoreEncryptionKeys(pid types.ProcessID, publicKey ecc.Point, privateKey *big.Int) error {
	x, y := publicKey.Point()
	eks := encryptionKeys{
		PublicKeyX: x,
		PublicKeyY: y,
		PrivateKey: privateKey,
	}
	w := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(w).Encode(eks); err != nil {
		return fmt.Errorf("could not encode encryption keys: %w", err)
	}
	tx := s.keys.WriteTx()
	if err := tx.Set(pid.Marshal(), w.Bytes()); err != nil {
		return fmt.Errorf("could not write encryption keys: %w", err)
	}
	return tx.Commit()
}

// LoadEncryptionKeys loads the encryption keys for a process. Returns ErrNotFound if the keys do not exist
func (s *Storage) LoadEncryptionKeys(pid types.ProcessID) (ecc.Point, *big.Int, error) {
	data, err := s.keys.Get(pid.Marshal())
	if err != nil {
		return nil, nil, fmt.Errorf("could not read encryption keys: %w", err)
	}
	if data == nil {
		return nil, nil, ErrNotFound
	}
	r := bytes.NewReader(data)
	var eks encryptionKeys
	if err := gob.NewDecoder(r).Decode(&eks); err != nil {
		return nil, nil, fmt.Errorf("could not decode encryption keys: %w", err)
	}
	pubKey := curves.New(curves.CurveTypeBN254).SetPoint(eks.PublicKeyX, eks.PublicKeyY)
	return pubKey, eks.PrivateKey, nil
}
