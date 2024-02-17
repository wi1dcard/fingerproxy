package metadata

import (
	"context"
)

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "fingerproxy context value " + k.name }

var (
	FingerproxyContextKey = &contextKey{"fingerproxy-metadata"}
)

func NewContext(ctx context.Context) (context.Context, *Metadata) {
	md := &Metadata{}
	newCtx := context.WithValue(ctx, FingerproxyContextKey, md)
	return newCtx, md
}

func FromContext(ctx context.Context) (*Metadata, bool) {
	data, ok := ctx.Value(FingerproxyContextKey).(*Metadata)
	return data, ok
}
