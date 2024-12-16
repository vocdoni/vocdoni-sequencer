package types

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// BallotMode is the struct to define the rules of a ballot
type BallotMode struct {
	MaxCount        uint8  `json:"maxCount"`
	ForceUniqueness bool   `json:"forceUniqueness"`
	MaxValue        BigInt `json:"maxValue"`
	MinValue        BigInt `json:"minValue"`
	MaxTotalCost    BigInt `json:"maxTotalCost"`
	MinTotalCost    BigInt `json:"minTotalCost"`
	CostExponent    uint8  `json:"costExponent"`
	CostFromWeight  bool   `json:"costFromWeight"`
}

// writeBigInt serializes a types.BigInt into the buffer as length + bytes
func writeBigInt(buf *bytes.Buffer, bi BigInt) error {
	data := bi.Bytes()
	length := uint32(len(data))
	err := binary.Write(buf, binary.BigEndian, length)
	if err != nil {
		return fmt.Errorf("failed to write big int length: %v", err)
	}
	if length > 0 {
		_, err = buf.Write(data)
		if err != nil {
			return fmt.Errorf("failed to write big int data: %v", err)
		}
	}
	return nil
}

// readBigInt deserializes a types.BigInt from the buffer
func readBigInt(buf *bytes.Reader, bi *BigInt) error {
	var length uint32
	err := binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return fmt.Errorf("failed to read big int length: %v", err)
	}
	data := make([]byte, length)
	if length > 0 {
		_, err = buf.Read(data)
		if err != nil {
			return fmt.Errorf("failed to read big int data: %v", err)
		}
	}
	bi.SetBytes(data)
	return nil
}

// Marshal serializes the BallotMode into a byte slice
func (b *BallotMode) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	// MaxCount (1 byte)
	err := buf.WriteByte(b.MaxCount)
	if err != nil {
		return nil, fmt.Errorf("failed to write MaxCount: %v", err)
	}

	// ForceUniqueness (1 byte: 0 or 1)
	force := byte(0)
	if b.ForceUniqueness {
		force = 1
	}
	err = buf.WriteByte(force)
	if err != nil {
		return nil, fmt.Errorf("failed to write ForceUniqueness: %v", err)
	}

	// MaxValue
	if err := writeBigInt(buf, b.MaxValue); err != nil {
		return nil, err
	}

	// MinValue
	if err := writeBigInt(buf, b.MinValue); err != nil {
		return nil, err
	}

	// MaxTotalCost
	if err := writeBigInt(buf, b.MaxTotalCost); err != nil {
		return nil, err
	}

	// MinTotalCost
	if err := writeBigInt(buf, b.MinTotalCost); err != nil {
		return nil, err
	}

	// CostExponent (1 byte)
	err = buf.WriteByte(b.CostExponent)
	if err != nil {
		return nil, fmt.Errorf("failed to write CostExponent: %v", err)
	}

	// CostFromWeight (1 byte: 0 or 1)
	costW := byte(0)
	if b.CostFromWeight {
		costW = 1
	}
	err = buf.WriteByte(costW)
	if err != nil {
		return nil, fmt.Errorf("failed to write CostFromWeight: %v", err)
	}

	return buf.Bytes(), nil
}

// Unmarshal deserializes the BallotMode from a byte slice
func (b *BallotMode) Unmarshal(data []byte) error {
	buf := bytes.NewReader(data)

	// MaxCount
	maxCount, err := buf.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read MaxCount: %v", err)
	}
	b.MaxCount = maxCount

	// ForceUniqueness
	force, err := buf.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read ForceUniqueness: %v", err)
	}
	b.ForceUniqueness = (force == 1)

	// MaxValue
	if err := readBigInt(buf, &b.MaxValue); err != nil {
		return err
	}

	// MinValue
	if err := readBigInt(buf, &b.MinValue); err != nil {
		return err
	}

	// MaxTotalCost
	if err := readBigInt(buf, &b.MaxTotalCost); err != nil {
		return err
	}

	// MinTotalCost
	if err := readBigInt(buf, &b.MinTotalCost); err != nil {
		return err
	}

	// CostExponent
	costExp, err := buf.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read CostExponent: %v", err)
	}
	b.CostExponent = costExp

	// CostFromWeight
	costW, err := buf.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read CostFromWeight: %v", err)
	}
	b.CostFromWeight = (costW == 1)

	return nil
}

// MarshalJSON implements json.Marshaler interface
func (b *BallotMode) MarshalJSON() ([]byte, error) {
	type Alias BallotMode
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(b),
	})
}

// UnmarshalJSON implements json.Unmarshaler interface
func (b *BallotMode) UnmarshalJSON(data []byte) error {
	type Alias BallotMode
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(b),
	}
	return json.Unmarshal(data, aux)
}
