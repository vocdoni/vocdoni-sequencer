package types

import (
	"encoding/json"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type GenericMetadata map[string]string

type MultilingualString map[string]string

type MediaMetadata struct {
	Header string `json:"header"`
	Logo   string `json:"logo"`
}

type Choice struct {
	Title MultilingualString `json:"title"`
	Value int                `json:"value"`
	Meta  GenericMetadata    `json:"meta"`
}

type Question struct {
	Title       MultilingualString `json:"title"`
	Description MultilingualString `json:"description"`
	Choices     []Choice           `json:"choices"`
	Meta        GenericMetadata    `json:"meta"`
}

type ProcessType struct {
	Name       string          `json:"name"`
	Properties GenericMetadata `json:"properties"`
}

type Metadata struct {
	Title       MultilingualString `json:"title"`
	Description MultilingualString `json:"description"`
	Media       MediaMetadata      `json:"media"`
	Questions   []Question         `json:"questions"`
	ProcessType ProcessType        `json:"processType"`
	BallotMode  BallotMode         `json:"ballotMode"`
}

type Process struct {
	ID             HexBytes       `json:"id,omitempty"`
	Status         uint8          `json:"status"`
	OrganizationId common.Address `json:"organizationId"`
	EncryptionKey  *EncryptionKey `json:"encryptionKey"`
	StateRoot      HexBytes       `json:"stateRoot"`
	Result         []*big.Int     `json:"result"`
	StartTime      time.Time      `json:"startTime"`
	Duration       time.Duration  `json:"duration"`
	MetadataURI    string         `json:"metadataURI"`
	BallotMode     *BallotMode    `json:"ballotMode"`
	Census         *Census        `json:"census"`
}

func (p *Process) String() string {
	data, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return string(data)
}

type EncryptionKey struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}

type Census struct {
	CensusOrigin uint8    `json:"censusOrigin"`
	MaxVotes     *big.Int `json:"maxVotes"`
	CensusRoot   HexBytes `json:"censusRoot"`
	CensusURI    string   `json:"censusURI"`
}

type OrganizationInfo struct {
	ID           common.Address `json:"id,omitempty"`
	Name         string         `json:"name"`
	MetadataURI  string         `json:"metadataURI"`
	ProcessCount uint32         `json:"processCount"`
}

func (o *OrganizationInfo) String() string {
	data, err := json.Marshal(o)
	if err != nil {
		return ""
	}
	return string(data)
}
