package koloblobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"testing"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

func withParams(b Backend, p params) *Store { return &Store{b: b, p: p} }

// fixedParams make every chunk exactly size bytes but the last, so tests choose the chunk count.
func fixedParams(fanout, size int) params {
	return params{fanout: fanout, minChunk: size, avgBits: 3, maxChunk: size, maxSize: MaxSize}
}

// Every chunk count up to a few levels writes a canonical tree that reads back, at every offset.
func TestTreeShapes(t *testing.T) {
	for _, fanout := range []int{2, 3, 5} {
		for n := 0; n <= 40; n++ {
			t.Run(fmt.Sprintf("fanout%d/chunks%d", fanout, n), func(t *testing.T) {
				p := fixedParams(fanout, 8)
				m := newMem()
				s := withParams(m, p)
				data := randBytes(byte(n), 8*n-n%2) // the last chunk is short for odd n
				if n == 0 {
					data = nil
				}
				key := NewKey()
				id := mustWrite(t, s, key, data)
				nodes, level := 0, n
				for {
					level = (level + fanout - 1) / fanout
					nodes += max(level, 1)
					if level <= 1 {
						break
					}
				}
				if m.len() != n+nodes {
					t.Fatalf("%d objects, want %d chunks and %d nodes", m.len(), n, nodes)
				}
				r, err := s.Open(context.Background(), id, key)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				for off := range len(data) {
					b := make([]byte, 3)
					k, err := r.ReadAt(b, int64(off))
					want := data[off:min(off+3, len(data))]
					if k != len(want) || !bytes.Equal(b[:k], want) || (k < 3) != (err == io.EOF) {
						t.Fatalf("ReadAt(3, %d) = %d, %v", off, k, err)
					}
				}
			})
		}
	}
}

func TestTreeTooTall(t *testing.T) {
	p := fixedParams(2, 1)
	key := NewKey()
	s := withParams(newMem(), p)
	id := mustWrite(t, s, key, randBytes(1, 64)) // 64 chunks: height 6
	if r := mustRead(t, s, id, key); !bytes.Equal(r, randBytes(1, 64)) {
		t.Fatal("wrong bytes")
	}
	_, err := s.Write(testCtx(t), key, bytes.NewReader(randBytes(1, 65)))
	wantErr(t, err, ErrTooLarge)
}

func TestSourceTooLarge(t *testing.T) {
	p := v0
	p.maxSize = 1000
	s := withParams(newMem(), p)
	key := NewKey()
	id := mustWrite(t, s, key, randBytes(1, 1000))
	if got := mustRead(t, s, id, key); len(got) != 1000 {
		t.Fatal(len(got))
	}
	_, err := s.Write(testCtx(t), key, bytes.NewReader(randBytes(1, 1001)))
	wantErr(t, err, ErrTooLarge)
}

// hostile builds node plaintexts by hand, seals them with the key and serves them.
type hostile struct {
	t   *testing.T
	m   *memBackend
	key Key
	ks  *keys
}

func newHostile(t *testing.T) *hostile {
	key := NewKey()
	ks, err := deriveKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	return &hostile{t: t, m: newMem(), key: key, ks: ks}
}

func (h *hostile) obj(label string, p []byte) Hash {
	return put(h.t, h.m, sealed(h.t, h.key, label, p))
}

func (h *hostile) chunk(n int) child {
	return child{h: h.obj(labelChunk, randBytes(9, n)), size: uint64(n)}
}

func (h *hostile) root(height int, kids ...child) ID {
	return ID(h.obj(labelRoot, encodeNode(&h.ks.commit, height, kids)))
}

func (h *hostile) node(height int, kids ...child) child {
	var size uint64
	for _, c := range kids {
		size += c.size
	}
	return child{h: h.obj(labelNode, encodeNode(nil, height, kids)), size: size}
}

// read opens id and reads it all, returning the first error.
func (h *hostile) read(id ID) error {
	s := New(h.m)
	r, err := s.Open(context.Background(), id, h.key)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = io.Copy(io.Discard, r)
	return err
}

func rawRoot(commit []byte, f func(e *kolocodec.Encoder)) []byte {
	var e kolocodec.Encoder
	e.PutFixed(commit)
	f(&e)
	return e.Bytes()
}

func TestHostileRoots(t *testing.T) {
	h := newHostile(t)
	small := h.chunk(10)
	full := h.chunk(MinChunkSize)
	commit := h.ks.commit[:]
	cases := map[string]struct {
		pt   []byte
		want error
	}{
		"height 0": {encodeNode(&h.ks.commit, 0, []child{small}), ErrCorrupt},
		"height 7": {encodeNode(&h.ks.commit, 7, []child{full, full}), ErrCorrupt},
		"257 children": {encodeNode(&h.ks.commit, 1, func() []child {
			k := make([]child, 257)
			for i := range k {
				k[i] = full
			}
			return k
		}()), ErrCorrupt},
		"height 2 with one child":    {encodeNode(&h.ks.commit, 2, []child{h.node(1, small)}), ErrCorrupt},
		"height 2 with no child":     {encodeNode(&h.ks.commit, 2, nil), ErrCorrupt},
		"chunk of size 0":            {encodeNode(&h.ks.commit, 1, []child{{h: small.h, size: 0}}), ErrCorrupt},
		"chunk over MaxChunkSize":    {encodeNode(&h.ks.commit, 1, []child{{h: small.h, size: MaxChunkSize + 1}}), ErrCorrupt},
		"short chunk before the end": {encodeNode(&h.ks.commit, 1, []child{small, small}), ErrCorrupt},
		"sizes over MaxSize": {encodeNode(&h.ks.commit, 2, []child{
			{h: small.h, size: MaxSize/2 + 1}, {h: small.h, size: MaxSize/2 + 1}}), ErrCorrupt},
		"child size over MaxSize": {rawRoot(commit, func(e *kolocodec.Encoder) {
			e.PutUvarint(2)
			e.PutUvarint(2)
			e.PutFixed(small.h[:])
			e.PutUvarint(MaxSize + 1)
			e.PutFixed(small.h[:])
			e.PutUvarint(1)
		}), ErrCorrupt},
		"trailing byte": {append(encodeNode(&h.ks.commit, 1, []child{small}), 0), ErrCorrupt},
		"non-minimal varint": {rawRoot(commit, func(e *kolocodec.Encoder) {
			e.PutFixed([]byte{0x81, 0x00}) // height 1 in two bytes
			e.PutUvarint(1)
			e.PutFixed(small.h[:])
			e.PutUvarint(small.size)
		}), ErrCorrupt},
		"truncated child": {encodeNode(&h.ks.commit, 1, []child{small})[:32+2+20], ErrCorrupt},
		"no commitment":   {[]byte{1, 0}, ErrCorrupt},
		"other commitment": {rawRoot(make([]byte, 32), func(e *kolocodec.Encoder) {
			e.PutUvarint(1)
			e.PutUvarint(0)
		}), ErrWrongKey},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			id := ID(h.obj(labelRoot, tc.pt))
			wantErr(t, h.read(id), tc.want)
		})
	}
	// A total over MaxSize is refused when the root is opened, before any read.
	big := encodeNode(&h.ks.commit, 2, []child{{h: small.h, size: MaxSize/2 + 1}, {h: small.h, size: MaxSize/2 + 1}})
	_, err := New(h.m).Open(context.Background(), ID(h.obj(labelRoot, big)), h.key)
	wantErr(t, err, ErrCorrupt)
	// Objects stored under their true hash but too short to be objects, or too long, are refused unopened.
	for _, n := range []int{0, 10, ObjectOverhead - 1, MaxObjectSize + 1} {
		bad := put(t, h.m, make([]byte, n))
		wantErr(t, h.read(h.root(1, child{h: bad, size: 1})), ErrCorrupt)
		wantErr(t, h.read(ID(bad)), ErrCorrupt)
	}
	// A node or chunk object given as the ID does not open as a root.
	wantErr(t, h.read(ID(h.node(1, small).h)), ErrWrongKey)
	wantErr(t, h.read(ID(small.h)), ErrWrongKey)
	// The canonical ones read.
	if err := h.read(h.root(1, small)); err != nil {
		t.Fatal(err)
	}
	if err := h.read(h.root(1)); err != nil {
		t.Fatal(err)
	}
}

func TestHostileInnerNodes(t *testing.T) {
	h := newHostile(t)
	full := h.chunk(MinChunkSize)
	small := h.chunk(10)
	fullNode := func() child {
		k := make([]child, Fanout)
		for i := range k {
			k[i] = full
		}
		return h.node(1, k...)
	}()
	cases := map[string]ID{
		"inner node not full":         h.root(2, h.node(1, full), h.node(1, small)),
		"wrong child height":          h.root(3, fullNode, h.node(2, h.node(1, small))),
		"size that does not add up":   h.root(2, fullNode, child{h: h.node(1, small).h, size: 11}),
		"chunk that is a node":        h.root(1, child{h: fullNode.h, size: 100}),
		"node that is a chunk":        h.root(2, fullNode, child{h: small.h, size: small.size}),
		"chunk shorter than its size": h.root(1, child{h: small.h, size: 11}),
		"chunk longer than its size":  h.root(1, child{h: small.h, size: 9}),
		"node that is a root":         h.root(2, fullNode, child{h: Hash(h.root(1, small)), size: small.size}),
		"node with a short chunk": h.root(2, func() child {
			k := make([]child, Fanout)
			for i := range k {
				k[i] = full
			}
			k[0] = small
			return h.node(1, k...)
		}(), h.node(1, small)),
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			wantErr(t, h.read(id), ErrCorrupt)
		})
	}
	if err := h.read(h.root(2, fullNode, h.node(1, small))); err != nil {
		t.Fatal(err)
	}
}

// lying serves a backend's objects through a function that may change them.
type lying struct {
	*memBackend
	f func(Hash, []byte) []byte
}

func (l *lying) Get(ctx context.Context, h Hash) ([]byte, error) {
	o, err := l.memBackend.Get(ctx, h)
	if err != nil {
		return nil, err
	}
	return l.f(h, o), nil
}

func TestStorageTampering(t *testing.T) {
	data := randBytes(11, 12<<20)
	m := newMem()
	key := NewKey()
	id := mustWrite(t, New(m), key, data)
	ks, _ := deriveKeys(key)
	root, err := New(m).openRoot(context.Background(), id, ks)
	if err != nil {
		t.Fatal(err)
	}
	c0, c1 := root.kids[0].h, root.kids[1].h
	cases := map[string]func(Hash, []byte) []byte{
		"flipped byte": func(h Hash, o []byte) []byte {
			if h == c1 {
				o = bytes.Clone(o)
				o[len(o)/2] ^= 1
			}
			return o
		},
		"reordered chunks": func(h Hash, o []byte) []byte {
			switch h {
			case c0:
				o, _ = m.Get(context.Background(), c1)
			case c1:
				o, _ = m.Get(context.Background(), c0)
			}
			return o
		},
		"truncated object": func(h Hash, o []byte) []byte {
			if h == c1 {
				o = o[:len(o)-1]
			}
			return o
		},
		"shorter than the overhead": func(h Hash, o []byte) []byte {
			if h == c1 {
				o = o[:ObjectOverhead-1]
			}
			return o
		},
		"over MaxObjectSize": func(h Hash, o []byte) []byte {
			if h == c1 {
				o = make([]byte, MaxObjectSize+1)
			}
			return o
		},
		"corrupt root": func(h Hash, o []byte) []byte {
			if h == Hash(id) {
				o = bytes.Clone(o)
				o[0] ^= 1
			}
			return o
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			s := New(&lying{m, f})
			r, err := s.Open(context.Background(), id, key)
			if err == nil {
				defer r.Close()
				var b []byte
				b, err = io.ReadAll(r)
				// Every byte before the bad chunk was verified and is correct.
				if !bytes.Equal(b, data[:len(b)]) || len(b) > int(root.kids[0].size) {
					t.Fatalf("returned %d bytes before the error", len(b))
				}
			}
			wantErr(t, err, ErrCorrupt)
			if s.Stats().Rejected == 0 {
				t.Fatal("no rejection counted")
			}
		})
	}
}

// A blob with a missing chunk reads up to it, fails with ErrNotFound there, and reads other ranges.
func TestMissingChunk(t *testing.T) {
	data := randBytes(12, 12<<20)
	m := newMem()
	key := NewKey()
	id := mustWrite(t, New(m), key, data)
	ks, _ := deriveKeys(key)
	root, _ := New(m).openRoot(context.Background(), id, ks)
	last := root.kids[len(root.kids)-1]
	delete(m.objs, last.h)
	r, err := New(m).Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	wantErr(t, err, ErrNotFound)
	if len(b) != len(data)-int(last.size) || !bytes.Equal(b, data[:len(b)]) {
		t.Fatalf("read %d bytes before the missing chunk", len(b))
	}
	buf := make([]byte, 100)
	if _, err := r.ReadAt(buf, 0); err != nil || !bytes.Equal(buf, data[:100]) {
		t.Fatal(err)
	}
}

func TestBackendErrors(t *testing.T) {
	boom := errors.New("disk on fire")
	m := newMem()
	key := NewKey()
	id := mustWrite(t, New(m), key, randBytes(1, 100))
	_, err := New(&failing{memBackend: m, get: boom}).Open(context.Background(), id, key)
	wantErr(t, err, boom)
	_, err = New(&failing{memBackend: newMem(), put: boom}).Write(testCtx(t), key, bytes.NewReader(randBytes(1, 100)))
	wantErr(t, err, boom)
	// The root's Put fails after the chunk's.
	_, err = New(&failing{memBackend: newMem(), put: boom, after: 1}).Write(testCtx(t), key, bytes.NewReader(randBytes(1, 100)))
	wantErr(t, err, boom)
	// A node's Put fails after the three chunks that fill it and start the next one.
	_, err = withParams(&failing{memBackend: newMem(), put: boom, after: 3}, fixedParams(2, 8)).Write(testCtx(t), key, bytes.NewReader(randBytes(1, 24)))
	wantErr(t, err, boom)
}

type failing struct {
	*memBackend
	get, put error
	after    int
}

func (f *failing) Get(ctx context.Context, h Hash) ([]byte, error) {
	if f.get != nil {
		return nil, f.get
	}
	return f.memBackend.Get(ctx, h)
}

func (f *failing) Put(ctx context.Context, h Hash, o []byte) error {
	if f.after > 0 {
		f.after--
		return f.memBackend.Put(ctx, h, o)
	}
	return f.put
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestSourceErrorAndCancel(t *testing.T) {
	boom := errors.New("source broke")
	_, err := New(newMem()).Write(testCtx(t), NewKey(), io.MultiReader(bytes.NewReader(make([]byte, 100)), errReader{boom}))
	wantErr(t, err, boom)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = New(newMem()).Write(ctx, NewKey(), bytes.NewReader(make([]byte, 100)))
	wantErr(t, err, context.Canceled)
}

// Concurrent ReadAt calls on one Reader return the right bytes.
func TestConcurrentReadAt(t *testing.T) {
	checkGoroutines(t)
	data := randBytes(13, 20<<20)
	s := New(newMem())
	key := NewKey()
	id := mustWrite(t, s, key, data)
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	errs := make(chan error, 8)
	for g := range 8 {
		go func() {
			rng := rand.New(rand.NewPCG(uint64(g), 1))
			for range 30 {
				off := rng.IntN(len(data))
				b := make([]byte, rng.IntN(2<<20)+1)
				n, err := r.ReadAt(b, int64(off))
				if err != nil && err != io.EOF {
					errs <- err
					return
				}
				if !bytes.Equal(b[:n], data[off:off+n]) {
					errs <- fmt.Errorf("wrong bytes at %d", off)
					return
				}
			}
			errs <- nil
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// A chunk over the largest chunk size is refused even when it decrypts to the size its node gives.
func TestChunkOverMaxChunkSize(t *testing.T) {
	h := newHostile(t)
	s := withParams(h.m, fixedParams(4, 8))
	for n, want := range map[int]error{8: nil, 9: ErrCorrupt} {
		r, err := s.Open(context.Background(), h.root(1, h.chunk(n)), h.key)
		if err == nil {
			_, err = io.Copy(io.Discard, r)
			r.Close()
		}
		if !errors.Is(err, want) {
			t.Fatalf("chunk of %d bytes: %v, want %v", n, err, want)
		}
	}
}

// An honest file of repeated content has equal nodes at different offsets, and reads them right.
func TestRepeatedNodes(t *testing.T) {
	p := fixedParams(4, 1000)
	m := newMem()
	s := withParams(m, p)
	key := NewKey()
	data := append(bytes.Repeat(randBytes(5, 4*1000), 9), 'x') // nine equal level 1 nodes, three equal level 2 nodes
	id := mustWrite(t, s, key, data)
	if m.len() >= len(data)/1000 {
		t.Fatalf("%d objects: the repeated content was not shared", m.len())
	}
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b := make([]byte, 7)
	for _, off := range []int64{int64(len(data)) - 3, 4000 + 10, 0, 16000 + 5, 8000} {
		n, err := r.ReadAt(b, off)
		if (err != nil && err != io.EOF) || !bytes.Equal(b[:n], data[off:off+int64(n)]) {
			t.Fatalf("ReadAt(%d) = %d, %v", off, n, err)
		}
	}
	if got, err := io.ReadAll(r); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("whole read: %v", err)
	}
}
