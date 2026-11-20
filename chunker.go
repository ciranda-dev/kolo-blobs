package koloblobs

import (
	"errors"
	"fmt"
	"io"
)

// chunker cuts a stream into content-defined chunks with FastCDC: a gear hash, cut-point skipping below
// the minimum and normalized chunking (a harder mask before the average size, an easier one after).
type chunker struct {
	r            io.Reader
	gear         *[256]uint64
	p            *params
	maskS, maskL uint64
	buf          []byte
	n            int // bytes in buf
	done         int // bytes of buf handed out by the last next
	eof          bool
}

func newChunker(r io.Reader, gear *[256]uint64, p *params) *chunker {
	return &chunker{
		r:     r,
		gear:  gear,
		p:     p,
		maskS: ^uint64(0) << (64 - (p.avgBits + 2)),
		maskL: ^uint64(0) << (64 - (p.avgBits - 2)),
	}
}

// next returns the next chunk, valid until the following call, or nil at the end of the stream.
func (c *chunker) next() ([]byte, error) {
	copy(c.buf, c.buf[c.done:c.n])
	c.n -= c.done
	c.done = 0
	for !c.eof && c.n < c.p.maxChunk {
		if c.n == len(c.buf) {
			// Grow by doubling, so a small file never costs a full chunk buffer.
			b := make([]byte, min(max(2*len(c.buf), 64<<10), c.p.maxChunk))
			copy(b, c.buf[:c.n])
			c.buf = b
		}
		m, err := io.ReadFull(c.r, c.buf[c.n:])
		c.n += m
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			c.eof = true
		} else if err != nil {
			return nil, fmt.Errorf("koloblobs: read source: %w", err)
		}
	}
	if c.n == 0 {
		return nil, nil
	}
	c.done = c.cut(c.buf[:c.n])
	return c.buf[:c.done], nil
}

// last reports whether the chunk next returned last is the final one of the stream.
func (c *chunker) last() bool { return c.eof && c.done == c.n }

// cut returns the length of the first chunk of b, which holds at most maxChunk bytes.
func (c *chunker) cut(b []byte) int {
	n := len(b)
	if n <= c.p.minChunk {
		return n
	}
	mid := min(1<<c.p.avgBits, n)
	var h uint64
	i := c.p.minChunk
	for ; i < mid; i++ {
		h = h<<1 + c.gear[b[i]]
		if h&c.maskS == 0 {
			return i + 1
		}
	}
	for ; i < n; i++ {
		h = h<<1 + c.gear[b[i]]
		if h&c.maskL == 0 {
			return i + 1
		}
	}
	return n
}

func (c *chunker) release() {
	clear(c.buf)
	c.buf = nil
}
