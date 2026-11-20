package koloblobs

import (
	"context"
	"errors"
	"fmt"

	kololog "github.com/ciranda-dev/kolo-log"
)

// FetchFunc returns the value of a content-log entry, checked by the transport; deleted or keyless entries
// wrap kololog.ErrDeleted or kololog.ErrKeyUnavailable.
type FetchFunc func(ctx context.Context, index uint64) ([]byte, error)

// LocateFunc returns the content-log index of the object h, or false if it does not know it.
type LocateFunc func(h Hash) (uint64, bool)

// RemoteBackend reads objects from a content log on another peer, one entry per object; it is read-only
// and safe for concurrent use if fetch and locate are.
type RemoteBackend struct {
	fetch  FetchFunc
	locate LocateFunc
}

// NewRemoteBackend returns a Backend that finds an object's entry with locate and gets it with fetch.
func NewRemoteBackend(fetch FetchFunc, locate LocateFunc) *RemoteBackend {
	return &RemoteBackend{fetch: fetch, locate: locate}
}

// Get fetches the entry holding h; an unknown object or a deleted or keyless entry is ErrNotFound.
func (b *RemoteBackend) Get(ctx context.Context, h Hash) ([]byte, error) {
	if b == nil || b.fetch == nil || b.locate == nil || ctx == nil {
		return nil, ErrInvalidArgument
	}
	i, ok := b.locate(h)
	if !ok {
		return nil, ErrNotFound
	}
	v, err := b.fetch(ctx, i)
	switch {
	case errors.Is(err, kololog.ErrDeleted), errors.Is(err, kololog.ErrKeyUnavailable):
		return nil, fmt.Errorf("%w: entry %d: %w", ErrNotFound, i, err)
	case err != nil:
		return nil, backendFailure("fetch entry %d: %w", i, err)
	}
	return v, nil
}

// Put returns ErrReadOnly: objects are written on the peer that owns the content log.
func (b *RemoteBackend) Put(context.Context, Hash, []byte) error { return ErrReadOnly }
