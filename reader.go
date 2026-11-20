package koloblobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Reader reads one blob as an io.Reader, io.ReaderAt and io.Seeker, checking every object before returning
// its bytes; it is safe for concurrent use, one call at a time.
type Reader struct {
	s    *Store
	ctx  context.Context // io's read methods take none, so the Reader keeps Open's
	size uint64

	mu   sync.Mutex
	ks   *keys // nil after Close
	root *node
	path [MaxHeight - 1]*node // path[h-1] is the last node of height h below the root that was used
	pos  int64

	chunk    []byte // plaintext of the last chunk read
	chunkOff uint64
	chunkOK  bool
}

// Open returns a Reader for the blob id under key after checking the root: ErrWrongKey for another key,
// ErrNotFound if the backend lacks it. The Reader passes ctx to every Backend.Get it makes.
func (s *Store) Open(ctx context.Context, id ID, key Key) (*Reader, error) {
	if s == nil || s.b == nil || ctx == nil {
		return nil, ErrInvalidArgument
	}
	ks, err := deriveKeys(key)
	if err != nil {
		return nil, err
	}
	root, err := s.openRoot(ctx, id, ks)
	if err != nil {
		ks.zero()
		return nil, err
	}
	return &Reader{s: s, ctx: ctx, size: root.size, ks: ks, root: root}, nil
}

// Size returns the blob's size in bytes.
func (r *Reader) Size() int64 { return int64(r.size) }

// ReadAt reads len(p) bytes from offset off, or up to the end of the blob with io.EOF.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.readAt(p, off)
}

// Read reads from the current offset and advances it.
func (r *Reader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.readAt(p, r.pos)
	r.pos += int64(n)
	if n > 0 && err == io.EOF {
		err = nil
	}
	return n, err
}

// Seek sets the offset of the next Read, as io.Seeker; an offset past the end reads io.EOF.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ks == nil {
		return 0, ErrClosed
	}
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = r.pos
	case io.SeekEnd:
		base = int64(r.size)
	default:
		return 0, fmt.Errorf("%w: whence %d", ErrInvalidArgument, whence)
	}
	if (offset > 0 && base > MaxSize-offset) || base+offset < 0 {
		return 0, fmt.Errorf("%w: offset out of range", ErrInvalidArgument)
	}
	r.pos = base + offset
	return r.pos, nil
}

// Close clears the reader's key material and chunk; later reads return ErrClosed. Closing twice is fine.
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ks != nil {
		r.ks.zero()
		r.ks = nil
	}
	clear(r.chunk[:cap(r.chunk)])
	r.chunk, r.chunkOK, r.path = nil, false, [MaxHeight - 1]*node{}
	return nil
}

func (r *Reader) readAt(p []byte, off int64) (int, error) {
	if r.ks == nil {
		return 0, ErrClosed
	}
	if off < 0 {
		return 0, fmt.Errorf("%w: negative offset", ErrInvalidArgument)
	}
	n := 0
	for n < len(p) {
		pos := uint64(off) + uint64(n)
		if pos >= r.size {
			return n, io.EOF
		}
		if !r.chunkOK || pos < r.chunkOff || pos-r.chunkOff >= uint64(len(r.chunk)) {
			if err := r.load(pos); err != nil {
				return n, err
			}
		}
		m := copy(p[n:], r.chunk[pos-r.chunkOff:])
		n += m
		r.s.bytesRead.Add(uint64(m))
	}
	return n, nil
}

// load walks from the root to the chunk holding pos, reusing the cached nodes on the way, and decrypts it.
func (r *Reader) load(pos uint64) error {
	r.chunkOK = false
	nd := r.root
	for nd.height > 1 {
		i, off := nd.find(pos)
		next := r.path[nd.height-2]
		if next == nil || next.h != nd.kids[i].h || next.off != off {
			var err error
			if next, err = r.s.openNode(r.ctx, nd, i, off, r.ks); err != nil {
				return err
			}
			r.path[nd.height-2] = next
		}
		nd = next
	}
	i, off := nd.find(pos)
	c := nd.kids[i]
	obj, err := r.s.fetch(r.ctx, c.h)
	if err != nil {
		return err
	}
	if cap(r.chunk) < len(obj)-ObjectOverhead {
		clear(r.chunk[:cap(r.chunk)])
		r.chunk = make([]byte, 0, len(obj)-ObjectOverhead)
	}
	pt, err := r.ks.open(r.chunk, labelChunk, obj)
	if errors.Is(err, errAuth) {
		r.s.rejected.Add(1)
		return fmt.Errorf("%w: chunk at offset %d does not open", ErrCorrupt, off)
	} else if err != nil {
		if errors.Is(err, ErrCorrupt) {
			r.s.rejected.Add(1)
		}
		return err
	}
	r.chunk = pt
	if uint64(len(pt)) != c.size {
		r.s.rejected.Add(1)
		return fmt.Errorf("%w: chunk at offset %d has %d bytes, its node says %d", ErrCorrupt, off, len(pt), c.size)
	}
	r.chunkOff, r.chunkOK = off, true
	return nil
}
