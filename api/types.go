package api

import (
	"github.com/google/uuid"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// NewCensus is the response to a new census creation request.
type NewCensus struct {
	Census uuid.UUID `json:"census"`
}

// CensusRoot is the response to a census root request.
type CensusRoot struct {
	Root types.HexBytes `json:"root"`
}

// CensusParticipant is a participant in a census.
type CensusParticipant struct {
	Key    types.HexBytes `json:"key"`
	Weight *types.BigInt  `json:"weight,omitempty"`
}

// CensusParticipants is a list of participants in a census.
type CensusParticipants struct {
	Participants []*CensusParticipant `json:"participants"`
}
