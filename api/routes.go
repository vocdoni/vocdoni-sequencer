package api

const (
	// ProcessEndpoint is the endpoint for creating a new voting process
	ProcessEndpoint = "/process"
	// PingEndpoint is the endpoint for checking the API status
	PingEndpoint = "/ping"

	// NewCensusEndpoint is the endpoint for creating a new census
	NewCensusEndpoint = "/census"
	// AddCensusParticipantsEndpoint is the endpoint for adding participants to a census
	AddCensusParticipantsEndpoint = "/census/participants"
	// GetCensusParticipantsEndpoint is the endpoint for getting the participants of a census
	GetCensusParticipantsEndpoint = "/census/participants"
	// GetCensusRootEndpoint is the endpoint for getting the root of a census
	GetCensusRootEndpoint = "/census/root"
	// GetCensusSizeEndpoint is the endpoint for getting the size of a census
	GetCensusSizeEndpoint = "/census/size"
	// DeleteCensusEndpoint is the endpoint for deleting a census
	DeleteCensusEndpoint = "/census"
	// GetCensusProofEndpoint is the endpoint for getting a proof of a census
	GetCensusProofEndpoint = "/census/proof"
)
