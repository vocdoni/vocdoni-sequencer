package types

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
