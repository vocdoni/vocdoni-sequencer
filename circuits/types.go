package circuits

// BallotMode is a struct that contains the common inputs for all the voters.
// The values of this struct should be the same for all the voters in the same
// process. Is a generic struct that can be used with any type of circuit input.
type BallotMode[T any] struct {
	MaxCount        T
	ForceUniqueness T
	MaxValue        T
	MinValue        T
	MaxTotalCost    T
	MinTotalCost    T
	CostExp         T
	CostFromWeight  T
}

func (b BallotMode[T]) List() []T {
	return []T{
		b.MaxCount,
		b.ForceUniqueness,
		b.MaxValue,
		b.MinValue,
		b.MaxTotalCost,
		b.MinTotalCost,
		b.CostExp,
		b.CostFromWeight,
	}
}

func (bm BallotMode[T]) Bytes() []byte {
	return []byte{0x00}
}
