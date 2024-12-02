package storage

const (
	metadataPrefix = "m/"
	censusPrefix   = "c/"
	processPrefix  = "p/"
	votePrefix     = "v/"
	authPrefix     = "au/"
	aggrPrefix     = "ag/"
)

func metadataKey(key string) []byte {
	return []byte(metadataPrefix + key)
}

func censusKey(key string) []byte {
	return []byte(censusPrefix + key)
}

func processKey(key string) []byte {
	return []byte(processPrefix + key)
}

func voteKey(key string) []byte {
	return []byte(votePrefix + key)
}

func authKey(key string) []byte {
	return []byte(authPrefix + key)
}

func aggrKey(key string) []byte {
	return []byte(aggrPrefix + key)
}
