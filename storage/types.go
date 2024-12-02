package storage

type GenericMetadata map[string]string

type MultilingualString map[string]string

type MediaMetadata struct {
	Header string `json:"header"`
	Logo   string `json:"logo"`
}

type Choice struct {
	Title   MultilingualString `json:"title"`
	Value   int                `json:"value"`
	Meta    GenericMetadata    `json:"meta"`
	Results string             `json:"results"`
	Answer  int                `json:"answer"`
}

type Question struct {
	Title       MultilingualString `json:"title"`
	Description MultilingualString `json:"description"`
	Choices     []Choice           `json:"choices"`
	NumAbstains int                `json:"numAbstains"`
	Meta        GenericMetadata    `json:"meta"`
}

type ProcessType struct {
	Name       string          `json:"name"`
	Properties GenericMetadata `json:"properties"`
}

type BallotMode struct {
	MaxCount       int  `json:"maxCount"`
	MaxValue       int  `json:"maxValue"`
	MinValue       int  `json:"minValue"`
	UniqueValues   bool `json:"uniqueValues"`
	MaxTotalCost   int  `json:"maxTotalCost"`
	MinTotalCost   int  `json:"minTotalCost"`
	CostExponent   int  `json:"costExponent"`
	CostFromWeight bool `json:"costFromWeight"`
}

type Metadata struct {
	Title       MultilingualString `json:"title"`
	Description MultilingualString `json:"description"`
	Media       MediaMetadata      `json:"media"`
	Questions   []Question         `json:"questions"`
	ProcessType ProcessType        `json:"processType"`
	BallotMode  BallotMode         `json:"ballotMode"`
}

type Census struct {
	Type          string `json:"type"`
	Weight        int    `json:"weight"`
	MaxCensusSize int    `json:"maxCensusSize"`
	Origin        string `json:"origin"`
	Root          string `json:"root"`
}

type CensusProof struct {
	Root     string   `json:"root"`
	Siblings []string `json:"siblings"`
}

type Process struct {
	ID         string     `json:"processID"`
	Census     Census     `json:"census"`
	BallotMode BallotMode `json:"ballotMode"`
	MetadataID string     `json:"metadataID"`
}

type PublicKey struct {
	Key [2]string `json:"key"`
}

type NullifierStatus struct {
	Status string `json:"status"` // [unknown, validated, settled]
}

type CircomProof struct {
	A        []string   `json:"pi_a"`
	B        [][]string `json:"pi_b"`
	C        []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
}

type Vote struct {
	InputsHash       string      `json:"inputsHash"`
	BallotMode       BallotMode  `json:"ballotMode"`
	Address          string      `json:"address"`
	UserWeight       int         `json:"userWeight"`
	EncryptionKey    PublicKey   `json:"encryptionKey"`
	Nullifier        string      `json:"nullifier"`
	Commitment       string      `json:"commitment"`
	ProcessID        string      `json:"processID"`
	EncryptedBallot  string      `json:"encryptedBallot"`
	CensusProof      CensusProof `json:"censusProof"`
	PublicKey        PublicKey   `json:"publicKey"`
	Signature        string      `json:"signature"`
	BallotInputsHash string      `json:"ballotInputsHash"`
	BallotProof      CircomProof `json:"ballotProof"`
}
