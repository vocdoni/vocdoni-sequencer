package api

const (
	pingEndpoint = "/ping"
	// metadataEndpoint is the api endpoint to upload metadata of a election
	// and get the metadataID to refer it later
	metadataEndpoint = "/metadata"
	// currentMetadataEndpoint is the api endpoint to get metadata by metadataID
	currentMetadataEndpoint = "/metadata/{metadataID}"
	// csvCensusEndpoint is the api endpoint to upload a csv file with the
	// census and get the created census information
	csvCensusEndpoint = "/censuses/csv"
	// currentCensusEndpoint is the api endpoint to get census information by
	// censusRoot
	currentCensusEndpoint = "/censuses/{censusRoot}"
	// electionsEndpoint is the api endpoint to create a new election
	electionsEndpoint = "/elections"
	// electionKeyEndpoint is the api endpoint to get the public encryption key
	// by the electionID [TODO: remove this endpoint]
	electionKeyEndpoint = "/elections/{electionID}/key"
	// checkNullifierEndpoint is the api endpoint to check if a nullifier is
	// already used in the election
	checkNullifierEndpoint = "/elections/{electionID}/nullifier"
	// voteEndpoint is the api endpoint to vote in an election
	votesEndpoint = "/votes"

	// processEndpoint is the api endpoint to create a new voting process
	newProcessEndpoint = "/process"
)
