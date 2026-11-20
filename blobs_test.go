package koloblobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"testing"
)

func TestRoundTripSizes(t *testing.T) {
	zk := zeroKey(t)
	for _, n := range []int{0, 1, 2, MinChunkSize - 1, MinChunkSize, MinChunkSize + 1, 1 << 20, MaxChunkSize - 1, MaxChunkSize, MaxChunkSize + 1, 4 << 20, 4<<20 + 1, 2 * MaxChunkSize, 2*MaxChunkSize + 1, 10 << 20} {
		for _, kind := range []string{"random", "zeros"} {
			t.Run(fmt.Sprint(kind, n), func(t *testing.T) {
				data, key := randBytes(byte(n), n), NewKey()
				if kind == "zeros" {
					data, key = make([]byte, n), zk
				}
				m := newMem()
				s := New(m)
				id := mustWrite(t, s, key, data)
				if got := mustRead(t, s, id, key); !bytes.Equal(got, data) {
					t.Fatalf("read back %d bytes that differ from the %d written", len(got), len(data))
				}
				if id2 := mustWrite(t, New(newMem()), key, data); id2 != id {
					t.Fatal("the same bytes and key gave another ID")
				}
			})
		}
	}
}

// Zeros under a key without a cut point make chunks of exactly MaxChunkSize, whose objects are exactly
// MaxObjectSize, the largest kolo-sync entry.
func TestMaxChunkObjects(t *testing.T) {
	key := zeroKey(t)
	for _, tc := range []struct {
		n     int
		sizes []int
	}{
		{MaxChunkSize, []int{MaxObjectSize}},
		{MaxChunkSize + 1, []int{MaxObjectSize, 1 + ObjectOverhead}},
		{4 << 20, []int{MaxObjectSize, 4<<20 - MaxChunkSize + ObjectOverhead}},
		{4<<20 + 1, []int{MaxObjectSize, 4<<20 + 1 - MaxChunkSize + ObjectOverhead}},
	} {
		m := newMem()
		id := mustWrite(t, New(m), key, make([]byte, tc.n))
		var got []int
		for h, o := range m.objs {
			if h != Hash(id) && len(o) > 1000 || len(o) == 1+ObjectOverhead {
				got = append(got, len(o))
			}
		}
		if len(got) != len(tc.sizes) || m.len() != len(tc.sizes)+1 {
			t.Fatalf("%d bytes: %d objects, chunk object sizes %v, want %v and a root", tc.n, m.len(), got, tc.sizes)
		}
		for _, w := range tc.sizes {
			found := false
			for _, g := range got {
				found = found || g == w
			}
			if !found {
				t.Fatalf("%d bytes: chunk object sizes %v, want %v", tc.n, got, tc.sizes)
			}
		}
	}
}

func TestEmptyBlob(t *testing.T) {
	m := newMem()
	s := New(m)
	key := NewKey()
	id := mustWrite(t, s, key, nil)
	if m.len() != 1 {
		t.Fatalf("an empty blob stored %d objects, want the root only", m.len())
	}
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	if r.Size() != 0 {
		t.Fatalf("size %d", r.Size())
	}
	if n, err := r.ReadAt(make([]byte, 1), 0); n != 0 || err != io.EOF {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	if n, err := r.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if n, err := r.ReadAt(nil, 0); n != 0 || err != nil {
		t.Fatalf("ReadAt of nothing = %d, %v", n, err)
	}
}

func TestDifferentKeysDifferentIDs(t *testing.T) {
	data := randBytes(1, 3<<20)
	s := New(newMem())
	a, b := mustWrite(t, s, NewKey(), data), mustWrite(t, s, NewKey(), data)
	if a == b {
		t.Fatal("two keys gave one ID")
	}
}

func TestWrongKey(t *testing.T) {
	s := New(newMem())
	key := NewKey()
	id := mustWrite(t, s, key, randBytes(2, 1000))
	_, err := s.Open(context.Background(), id, NewKey())
	wantErr(t, err, ErrWrongKey)
	if s.Stats().Rejected != 1 {
		t.Fatalf("rejected = %d", s.Stats().Rejected)
	}
}

func TestMissingRoot(t *testing.T) {
	_, err := New(newMem()).Open(context.Background(), ID{1}, NewKey())
	wantErr(t, err, ErrNotFound)
}

// Edits to a version written with the same key store only the chunks around them.
func TestDedupAcrossVersions(t *testing.T) {
	key := NewKey()
	v1 := randBytes(3, 64<<20)
	m := newMem()
	s := New(m)
	mustWrite(t, s, key, v1)
	before := m.len()
	mid := len(v1) / 2
	v2 := append(append(append([]byte{}, v1[:mid]...), []byte("inserted")...), v1[mid:]...)
	id2 := mustWrite(t, s, key, v2)
	added := m.len() - before
	// The chunk around the edit, maybe its neighbour, the level 1 node and the root.
	if added > 4 {
		t.Fatalf("an 8-byte insertion stored %d new objects", added)
	}
	if !bytes.Equal(mustRead(t, s, id2, key), v2) {
		t.Fatal("second version reads back wrong")
	}
	// The same version again stores nothing.
	before = m.len()
	if mustWrite(t, s, key, v2) != id2 || m.len() != before {
		t.Fatal("writing the same version again stored objects or changed the ID")
	}
}

func TestRangeReads(t *testing.T) {
	data := randBytes(4, 40<<20)
	m := newMem()
	s := New(m)
	key := NewKey()
	id := mustWrite(t, s, key, data)
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rng := rand.New(rand.NewPCG(1, 2))
	for range 200 {
		off := rng.Int64N(int64(len(data)) + 10)
		n := rng.IntN(3 << 20)
		buf := make([]byte, n)
		got, err := r.ReadAt(buf, off)
		end := min(off+int64(n), int64(len(data)))
		want := []byte{}
		if off < int64(len(data)) {
			want = data[off:end]
		}
		if got != len(want) || !bytes.Equal(buf[:got], want) {
			t.Fatalf("ReadAt(%d, %d) = %d bytes, want %d", n, off, got, len(want))
		}
		if (got < n) != (err == io.EOF) || (err != nil && err != io.EOF) {
			t.Fatalf("ReadAt(%d, %d) error = %v with %d bytes", n, off, err, got)
		}
	}
	// The last byte, and offsets at or past the end.
	if n, err := r.ReadAt(make([]byte, 5), int64(len(data))-1); n != 1 || err != io.EOF {
		t.Fatalf("ReadAt(size-1) = %d, %v", n, err)
	}
	for _, off := range []int64{int64(len(data)), int64(len(data)) + 1} {
		if n, err := r.ReadAt(make([]byte, 5), off); n != 0 || err != io.EOF {
			t.Fatalf("ReadAt(%d) = %d, %v", off, n, err)
		}
	}
	// A section reader gives start, end and length ranges.
	sec := io.NewSectionReader(r, 5<<20, 3<<20)
	b, err := io.ReadAll(sec)
	if err != nil || !bytes.Equal(b, data[5<<20:8<<20]) {
		t.Fatalf("section read %d bytes, %v", len(b), err)
	}
}

// A range read fetches the root once, then one node per level and only the chunks under the range.
func TestRangeReadFetchesOnlyNeededChunks(t *testing.T) {
	data := randBytes(5, 40<<20)
	m := newMem()
	p := v0
	p.fanout = 4 // three levels from about 33 chunks
	s := withParams(m, p)
	key := NewKey()
	id := mustWrite(t, s, key, data)
	m.resetGets()
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.root.height != 3 {
		t.Fatalf("height %d, want 3", r.root.height)
	}
	buf := make([]byte, 10)
	off := int64(30 << 20)
	if _, err := r.ReadAt(buf, off); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, data[off:off+10]) {
		t.Fatal("wrong bytes")
	}
	if g := m.totalGets(); g != 4 {
		t.Fatalf("a 10-byte read fetched %d objects, want the root, two nodes and a chunk", g)
	}
	// Reading inside the same chunk fetches nothing more.
	if _, err := r.ReadAt(buf, off+20); err != nil || m.totalGets() != 4 {
		t.Fatalf("a read in the cached chunk fetched again: %d gets, %v", m.totalGets(), err)
	}
}

func TestSeekAndRead(t *testing.T) {
	data := randBytes(6, 3<<20)
	s := New(newMem())
	key := NewKey()
	id := mustWrite(t, s, key, data)
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, tc := range []struct {
		off    int64
		whence int
		want   int64
	}{{100, io.SeekStart, 100}, {50, io.SeekCurrent, 150}, {-10, io.SeekEnd, int64(len(data)) - 10}, {10, io.SeekEnd, int64(len(data)) + 10}} {
		got, err := r.Seek(tc.off, tc.whence)
		if err != nil || got != tc.want {
			t.Fatalf("Seek(%d, %d) = %d, %v", tc.off, tc.whence, got, err)
		}
	}
	if n, err := r.Read(make([]byte, 5)); n != 0 || err != io.EOF {
		t.Fatalf("Read past the end = %d, %v", n, err)
	}
	if _, err := r.Seek(int64(len(data))-3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 10)
	if n, err := r.Read(b); n != 3 || err != nil || !bytes.Equal(b[:3], data[len(data)-3:]) {
		t.Fatalf("Read at the end = %d, %v", n, err)
	}
	for _, tc := range []struct {
		off    int64
		whence int
	}{{-1, io.SeekStart}, {1, 3}, {MaxSize, io.SeekEnd}, {-int64(len(data)) - 1, io.SeekEnd}} {
		if _, err := r.Seek(tc.off, tc.whence); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("Seek(%d, %d) = %v", tc.off, tc.whence, err)
		}
	}
	if _, err := r.ReadAt(b, -1); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ReadAt(-1) = %v", err)
	}
}

func TestClose(t *testing.T) {
	s := New(newMem())
	key := NewKey()
	id := mustWrite(t, s, key, randBytes(7, 1000))
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	ks := r.ks
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if *ks != (keys{}) {
		t.Fatal("Close left the subkeys in memory")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = r.Read(make([]byte, 1))
	wantErr(t, err, ErrClosed)
	_, err = r.ReadAt(make([]byte, 1), 0)
	wantErr(t, err, ErrClosed)
	_, err = r.Seek(0, io.SeekStart)
	wantErr(t, err, ErrClosed)
}

func TestInvalidArguments(t *testing.T) {
	ctx := testCtx(t)
	var nilStore *Store
	if _, err := nilStore.Write(ctx, NewKey(), bytes.NewReader(nil)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := New(nil).Write(ctx, NewKey(), bytes.NewReader(nil)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := New(newMem()).Write(ctx, NewKey(), nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := New(nil).Open(context.Background(), ID{}, NewKey()); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := nilStore.Open(context.Background(), ID{}, NewKey()); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	var nilCtx context.Context
	if _, err := New(newMem()).Write(nilCtx, NewKey(), bytes.NewReader(nil)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
}
