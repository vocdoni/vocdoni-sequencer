package api

const (
	// PingEndpoint is the endpoint for checking the API status
	PingEndpoint = "/ping"
	// ProcessesEndpoint is the endpoint for creating a new voting process
	ProcessesEndpoint = "/processes"
	// ProcessEndpoint is the endpoint to get the process info
	ProcessURLParam = "processId"
	ProcessEndpoint = "/processes/{" + ProcessURLParam + "}"
	// TestSetProcessEndpoint and TestProcessEndpoint is the endpoint for store
	// and retrieve the process info for testing. In a real scenatio, this
	// information should be in the smart contract.
	TestSetProcessEndpoint = "/processes/test"
	TestProcessEndpoint    = "/processes/test/{" + ProcessURLParam + "}"
	// VotesEndpoint is the endpoint for submitting a vote
	VotesEndpoint = "/votes"
)
