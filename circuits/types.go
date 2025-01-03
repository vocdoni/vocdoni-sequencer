package circuits

// BallotMode is a struct that contains the common inputs for all the voters.
// The values of this struct should be the same for all the voters in the same
// process. Is a generic struct that can be used with any type of circuit input.
type BallotMode[T any] struct {
	MaxCount         T
	ForceUniqueness  T
	MaxValue         T
	MinValue         T
	MaxTotalCost     T
	MinTotalCost     T
	CostExp          T
	CostFromWeight   T
	EncryptionPubKey [2]T
}
