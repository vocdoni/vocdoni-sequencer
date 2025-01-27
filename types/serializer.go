package types

type Serializer[T any] interface {
	Serialize() []T
}
