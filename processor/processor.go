package processor

import "context"

type Processor interface {
	Start(context.Context) error
	Stop() error
}
