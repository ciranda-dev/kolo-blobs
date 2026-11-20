package koloblobs

import (
	"context"
	"iter"
)

// Objects lists the hash of every object of the blob id, root first, fetching the nodes but not the chunks;
// it stops at the first error, yielded with a zero Hash.
func (s *Store) Objects(ctx context.Context, id ID, key Key) iter.Seq2[Hash, error] {
	return func(yield func(Hash, error) bool) {
		if s == nil || s.b == nil || ctx == nil {
			yield(Hash{}, ErrInvalidArgument)
			return
		}
		ks, err := deriveKeys(key)
		if err != nil {
			yield(Hash{}, err)
			return
		}
		defer ks.zero()
		root, err := s.openRoot(ctx, id, ks)
		if err != nil {
			yield(Hash{}, err)
			return
		}
		if yield(Hash(id), nil) {
			s.walk(ctx, root, ks, yield)
		}
	}
}

// walk yields the children of nd and, for a node above the chunks, everything under each child.
func (s *Store) walk(ctx context.Context, nd *node, ks *keys, yield func(Hash, error) bool) bool {
	for i, c := range nd.kids {
		if !yield(c.h, nil) {
			return false
		}
		if nd.height == 1 {
			continue
		}
		off := nd.off
		if i > 0 {
			off += nd.ends[i-1]
		}
		child, err := s.openNode(ctx, nd, i, off, ks)
		if err != nil {
			yield(Hash{}, err)
			return false
		}
		if !s.walk(ctx, child, ks, yield) {
			return false
		}
	}
	return true
}
