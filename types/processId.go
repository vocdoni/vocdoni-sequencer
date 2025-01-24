package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// ProcessID is the type to identify a voting process. It is composed of:
// - ChainID (4 bytes)
// - Address (20 bytes)
// - Nonce (8 bytes)
type ProcessID struct {
	Address common.Address
	Nonce   uint64
	ChainID uint32
}

// Marshal encodes ProcessId to bytes:
func (p *ProcessID) Marshal() []byte {
	chainId := make([]byte, 4)
	binary.BigEndian.PutUint32(chainId, p.ChainID)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, p.Nonce)

	var id bytes.Buffer
	id.Write(chainId[:4])
	id.Write(p.Address.Bytes()[:20])
	id.Write(nonce[:8])
	return id.Bytes()
}

// UnMarshal decodes bytes to ProcessId.
func (p *ProcessID) Unmarshal(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid ProcessID length: %d", len(data))
	}
	p.ChainID = binary.BigEndian.Uint32(data[:4])
	p.Address = common.BytesToAddress(data[4:24])
	p.Nonce = binary.BigEndian.Uint64(data[24:32])
	return nil
}

// MarshalBinary implements the BinaryMarshaler interface
func (p *ProcessID) MarshalBinary() (data []byte, err error) {
	return p.Marshal(), nil
}

// UnmarshalBinary implements the BinaryMarshaler interface
func (p *ProcessID) UnmarshalBinary(data []byte) error {
	return p.Unmarshal(data)
}

// String returns a human readable representation of process ID
func (p *ProcessID) String() string {
	return hex.EncodeToString(p.Marshal())
}
