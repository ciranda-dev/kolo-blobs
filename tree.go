package koloblobs

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

// child is one entry of a node: an object hash and the plaintext size under it.
type child struct {
	h    Hash
	size uint64
}

// node is a decoded tree node placed in its blob: it covers [off, off+size).
type node struct {
	h      Hash
	height int
	off    uint64
	size   uint64
	last   bool // the last node of its level, so it may be partly full
	kids   []child
	ends   []uint64 // ends[i] is the end of child i, relative to off
}

func encodeNode(commit *[32]byte, height int, kids []child) []byte {
	var e kolocodec.Encoder
	if commit != nil {
		e.PutFixed(commit[:])
	}
	e.PutUvarint(uint64(height))
	e.PutUvarint(uint64(len(kids)))
	for _, c := range kids {
		e.PutFixed(c.h[:])
		e.PutUvarint(c.size)
	}
	return e.Bytes()
}

// decodeNode parses a node's plaintext; a root starts with the key commitment. It checks the encoding,
// the child count and that sizes add up within maxSize; the caller checks the node against its parent.
func decodeNode(b []byte, root bool, p *params) (commit [32]byte, height int, kids []child, err error) {
	d := kolocodec.NewDecoder(b)
	if root {
		c, err := d.Fixed(32)
		if err != nil {
			return commit, 0, nil, malformed(err)
		}
		copy(commit[:], c)
	}
	h, err := d.UvarintMax(MaxHeight)
	if err != nil {
		return commit, 0, nil, malformed(err)
	}
	if h == 0 {
		return commit, 0, nil, fmt.Errorf("%w: node of height 0", ErrCorrupt)
	}
	n, err := d.UvarintMax(uint64(p.fanout))
	if err != nil {
		return commit, 0, nil, malformed(err)
	}
	switch {
	case n == 0 && !(root && h == 1):
		return commit, 0, nil, fmt.Errorf("%w: node of height %d without children", ErrCorrupt, h)
	case n == 1 && root && h > 1:
		return commit, 0, nil, fmt.Errorf("%w: root of height %d with one child", ErrCorrupt, h)
	}
	kids = make([]child, n)
	var sum uint64
	for i := range kids {
		hb, err := d.Fixed(HashSize)
		if err != nil {
			return commit, 0, nil, malformed(err)
		}
		copy(kids[i].h[:], hb)
		s, err := d.UvarintMax(p.maxSize)
		if err != nil {
			return commit, 0, nil, malformed(err)
		}
		if s == 0 || s > p.maxSize-sum {
			return commit, 0, nil, fmt.Errorf("%w: child %d has size %d", ErrCorrupt, i, s)
		}
		sum += s
		kids[i].size = s
	}
	if err := d.Done(); err != nil {
		return commit, 0, nil, malformed(err)
	}
	return commit, int(h), kids, nil
}

func malformed(err error) error { return fmt.Errorf("%w: malformed node: %w", ErrCorrupt, err) }

// place checks a decoded node against what its parent says and returns it placed in the blob.
func place(h Hash, height int, kids []child, off, size uint64, last bool, p *params) (*node, error) {
	n := len(kids)
	if !last && n != p.fanout {
		return nil, fmt.Errorf("%w: inner node at offset %d with %d children", ErrCorrupt, off, n)
	}
	nd := &node{h: h, height: height, off: off, size: size, last: last, kids: kids, ends: make([]uint64, n)}
	var end uint64
	for i, c := range kids {
		if height == 1 {
			lastChunk := last && i == n-1
			if c.size > uint64(p.maxChunk) || (!lastChunk && c.size < uint64(p.minChunk)) {
				return nil, fmt.Errorf("%w: chunk of %d bytes at offset %d", ErrCorrupt, c.size, off+end)
			}
		}
		end += c.size
		nd.ends[i] = end
	}
	if end != size {
		return nil, fmt.Errorf("%w: node at offset %d holds %d bytes, its parent says %d", ErrCorrupt, off, end, size)
	}
	return nd, nil
}

// find returns the child holding the blob offset pos, which the node covers, and that child's offset.
func (nd *node) find(pos uint64) (int, uint64) {
	rel := pos - nd.off
	i := sort.Search(len(nd.ends), func(i int) bool { return nd.ends[i] > rel })
	start := uint64(0)
	if i > 0 {
		start = nd.ends[i-1]
	}
	return i, nd.off + start
}

// builder builds the tree bottom-up while chunks arrive: levels[i] holds the children of the pending node
// of height i+1. A full level is written out only when one more child arrives, so the top level left at
// the end is the root.
type builder struct {
	s      *Store
	ctx    context.Context
	ks     *keys
	levels [][]child
	buf    []byte
}

func (b *builder) add(level int, c child) error {
	if level == len(b.levels) {
		if level == MaxHeight {
			return fmt.Errorf("%w: tree taller than %d levels", ErrTooLarge, MaxHeight)
		}
		b.levels = append(b.levels, make([]child, 0, b.s.p.fanout))
	}
	if len(b.levels[level]) == b.s.p.fanout {
		up, err := b.emit(level, false)
		if err != nil {
			return err
		}
		if err := b.add(level+1, up); err != nil {
			return err
		}
	}
	b.levels[level] = append(b.levels[level], c)
	return nil
}

// emit writes the pending node of a level and empties it.
func (b *builder) emit(level int, root bool) (child, error) {
	kids := b.levels[level]
	var commit *[32]byte
	label := labelNode
	if root {
		commit, label = &b.ks.commit, labelRoot
	}
	var size uint64
	for _, c := range kids {
		size += c.size
	}
	pt := encodeNode(commit, level+1, kids)
	var err error
	b.buf, err = b.ks.seal(b.buf[:0], label, pt)
	if err != nil {
		return child{}, err
	}
	h, err := b.s.putObject(b.ctx, b.buf)
	if err != nil {
		return child{}, err
	}
	b.levels[level] = kids[:0]
	return child{h: h, size: size}, nil
}

func (b *builder) finish() (Hash, error) {
	if len(b.levels) == 0 {
		b.levels = append(b.levels, nil)
	}
	for i := 0; i < len(b.levels)-1; i++ {
		up, err := b.emit(i, false)
		if err != nil {
			return Hash{}, err
		}
		if err := b.add(i+1, up); err != nil {
			return Hash{}, err
		}
	}
	root, err := b.emit(len(b.levels)-1, true)
	return root.h, err
}

// openRoot fetches, decrypts and checks a blob's root.
func (s *Store) openRoot(ctx context.Context, id ID, ks *keys) (*node, error) {
	obj, err := s.fetch(ctx, Hash(id))
	if err != nil {
		return nil, err
	}
	pt, err := ks.open(nil, labelRoot, obj)
	if errors.Is(err, errAuth) {
		s.rejected.Add(1)
		return nil, fmt.Errorf("%w: the root does not open", ErrWrongKey)
	} else if err != nil {
		if errors.Is(err, ErrCorrupt) {
			s.rejected.Add(1)
		}
		return nil, err
	}
	defer clear(pt) // the root holds the key commitment
	commit, height, kids, err := decodeNode(pt, true, &s.p)
	if err != nil {
		s.rejected.Add(1)
		return nil, err
	}
	if subtle.ConstantTimeCompare(commit[:], ks.commit[:]) != 1 {
		s.rejected.Add(1)
		return nil, fmt.Errorf("%w: the root commits to another key", ErrWrongKey)
	}
	var size uint64
	for _, c := range kids {
		size += c.size
	}
	nd, err := place(Hash(id), height, kids, 0, size, true, &s.p)
	if err != nil {
		s.rejected.Add(1)
	}
	return nd, err
}

// openNode fetches the child i of parent, which is a node, and checks it.
func (s *Store) openNode(ctx context.Context, parent *node, i int, off uint64, ks *keys) (*node, error) {
	c := parent.kids[i]
	obj, err := s.fetch(ctx, c.h)
	if err != nil {
		return nil, err
	}
	pt, err := ks.open(nil, labelNode, obj)
	if errors.Is(err, errAuth) {
		s.rejected.Add(1)
		return nil, fmt.Errorf("%w: node at offset %d does not open", ErrCorrupt, off)
	} else if err != nil {
		if errors.Is(err, ErrCorrupt) {
			s.rejected.Add(1)
		}
		return nil, err
	}
	_, height, kids, err := decodeNode(pt, false, &s.p)
	if err == nil && height != parent.height-1 {
		err = fmt.Errorf("%w: node of height %d under a node of height %d", ErrCorrupt, height, parent.height)
	}
	var nd *node
	if err == nil {
		nd, err = place(c.h, height, kids, off, c.size, parent.last && i == len(parent.kids)-1, &s.p)
	}
	if err != nil {
		s.rejected.Add(1)
	}
	return nd, err
}
