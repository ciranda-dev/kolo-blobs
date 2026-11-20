package koloblobs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// Objects lists the root first and every node and chunk once, fetching nodes but no chunk.
func TestObjects(t *testing.T) {
	m := newMem()
	p := v0
	p.fanout = 4 // three levels from about 33 chunks
	s := withParams(m, p)
	key := NewKey()
	id := mustWrite(t, s, key, randBytes(14, 40<<20))
	m.resetGets()
	seen := map[Hash]bool{}
	first := true
	for h, err := range s.Objects(testCtx(t), id, key) {
		if err != nil {
			t.Fatal(err)
		}
		if first && h != Hash(id) {
			t.Fatal("the root is not listed first")
		}
		first = false
		if seen[h] {
			t.Fatal("an object listed twice")
		}
		seen[h] = true
	}
	if len(seen) != m.len() {
		t.Fatalf("listed %d of %d objects", len(seen), m.len())
	}
	ks, _ := deriveKeys(key)
	for h, n := range m.gets {
		_, errNode := ks.open(nil, labelNode, m.objs[h])
		_, errRoot := ks.open(nil, labelRoot, m.objs[h])
		if n != 1 || (errNode != nil && errRoot != nil) {
			t.Fatalf("listing fetched an object %d times, or a chunk", n)
		}
	}
	// Stopping early, at the root and inside the tree, and errors.
	for _, stop := range []int{1, 3, 10} {
		n := 0
		for range s.Objects(testCtx(t), id, key) {
			if n++; n == stop {
				break
			}
		}
	}
	var nilCtx context.Context
	for _, err := range s.Objects(nilCtx, id, key) {
		wantErr(t, err, ErrInvalidArgument)
	}
	var errs []error
	for _, err := range s.Objects(testCtx(t), ID{1}, key) {
		errs = append(errs, err)
	}
	if len(errs) != 1 || !errors.Is(errs[0], ErrNotFound) {
		t.Fatalf("missing root: %v", errs)
	}
	root, _ := s.openRoot(testCtx(t), id, ks)
	delete(m.objs, root.kids[1].h)
	var last error
	n := 0
	for _, err := range s.Objects(testCtx(t), id, key) {
		n++
		last = err
	}
	wantErr(t, last, ErrNotFound)
	if n < 2 {
		t.Fatalf("%d items before the missing node", n)
	}
	for _, err := range New(nil).Objects(testCtx(t), id, key) {
		wantErr(t, err, ErrInvalidArgument)
	}
}

func TestLogBackendIndex(t *testing.T) {
	_, l, _ := storeLog(t)
	b := NewLogBackend(l)
	s := New(b)
	key := NewKey()
	id := mustWrite(t, s, key, randBytes(15, 3<<20))
	n := 0
	for h, err := range s.Objects(testCtx(t), id, key) {
		if err != nil {
			t.Fatal(err)
		}
		i, err := NewLogBackend(l).Index(context.Background(), h)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := l.Get(i)
		if hashOf(v) != h {
			t.Fatalf("entry %d does not hold the object", i)
		}
		n++
	}
	if uint64(n) != l.Len() {
		t.Fatalf("%d objects in %d entries", n, l.Len())
	}
	_, err := b.Index(context.Background(), Hash{1})
	wantErr(t, err, ErrNotFound)
	var nilB *LogBackend
	_, err = nilB.Index(context.Background(), Hash{})
	wantErr(t, err, ErrInvalidArgument)
}

func TestRemoteBackend(t *testing.T) {
	obj := []byte("an object")
	boom := errors.New("connection lost")
	locate := func(h Hash) (uint64, bool) { return 7, h == hashOf(obj) }
	for _, tc := range []struct {
		err  error
		want error
	}{{kololog.ErrDeleted, ErrNotFound}, {kololog.ErrKeyUnavailable, ErrNotFound}, {boom, boom}, {nil, nil}} {
		b := NewRemoteBackend(func(_ context.Context, i uint64) ([]byte, error) {
			if i != 7 {
				t.Fatalf("fetched entry %d", i)
			}
			if tc.err != nil {
				return nil, tc.err
			}
			return obj, nil
		}, locate)
		v, err := b.Get(testCtx(t), hashOf(obj))
		if !errors.Is(err, tc.want) || (tc.want == nil && !bytes.Equal(v, obj)) {
			t.Fatalf("fetch error %v: Get = %q, %v", tc.err, v, err)
		}
		if tc.want != ErrNotFound && errors.Is(err, ErrNotFound) {
			t.Fatalf("fetch error %v: Get = %v, which is ErrNotFound", tc.err, err)
		}
		if tc.want != nil && tc.err != nil && !errors.Is(err, tc.err) {
			t.Fatalf("%v does not wrap %v", err, tc.err)
		}
	}
	b := NewRemoteBackend(func(context.Context, uint64) ([]byte, error) { return obj, nil }, locate)
	_, err := b.Get(testCtx(t), Hash{1})
	wantErr(t, err, ErrNotFound)
	wantErr(t, b.Put(context.Background(), hashOf(obj), obj), ErrReadOnly)
	_, err = NewRemoteBackend(nil, locate).Get(testCtx(t), Hash{})
	wantErr(t, err, ErrInvalidArgument)
	_, err = NewRemoteBackend(func(context.Context, uint64) ([]byte, error) { return obj, nil }, nil).Get(testCtx(t), Hash{})
	wantErr(t, err, ErrInvalidArgument)
	var nilB *RemoteBackend
	_, err = nilB.Get(testCtx(t), Hash{})
	wantErr(t, err, ErrInvalidArgument)
	var nilCtx context.Context
	_, err = NewRemoteBackend(func(context.Context, uint64) ([]byte, error) { return obj, nil }, locate).Get(nilCtx, hashOf(obj))
	wantErr(t, err, ErrInvalidArgument)
	// Bytes that do not match the hash are refused by the Store.
	s := New(NewRemoteBackend(func(context.Context, uint64) ([]byte, error) {
		return []byte("other bytes that are long enough to be an object."), nil
	}, func(Hash) (uint64, bool) { return 0, true }))
	_, err = s.Open(testCtx(t), ID{1}, NewKey())
	wantErr(t, err, ErrCorrupt)
}

func TestRemoteFetchErrorNamedOnce(t *testing.T) {
	boom := errors.New("connection lost")
	key := NewKey()
	mem := newMem()
	id, err := New(mem).Write(testCtx(t), key, bytes.NewReader(make([]byte, 3*MaxChunkSize)))
	if err != nil {
		t.Fatal(err)
	}
	var objs [][]byte
	index := map[Hash]uint64{}
	for h, o := range mem.objs {
		index[h] = uint64(len(objs))
		objs = append(objs, o)
	}
	var down atomic.Bool
	s := New(NewRemoteBackend(func(_ context.Context, i uint64) ([]byte, error) {
		if down.Load() {
			return nil, boom
		}
		return objs[i], nil
	}, func(h Hash) (uint64, bool) { i, ok := index[h]; return i, ok }))
	check := func(what string, err error) {
		t.Helper()
		wantErr(t, err, boom)
		if n := strings.Count(err.Error(), "koloblobs: "); n != 1 {
			t.Fatalf("%s = %q, has %d prefixes, want 1", what, err, n)
		}
	}
	down.Store(true)
	_, err = s.Open(testCtx(t), id, key)
	check("Open", err)
	down.Store(false)
	r, err := s.Open(testCtx(t), id, key)
	if err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	_, err = io.ReadAll(r)
	check("Read", err)
}

type cancelling struct{ *memBackend }

func (c cancelling) Get(ctx context.Context, h Hash) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestContextEndsReads(t *testing.T) {
	m := newMem()
	s := New(m)
	key := NewKey()
	id := mustWrite(t, s, key, randBytes(16, 3<<20))
	done, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Open(done, id, key)
	wantErr(t, err, context.Canceled)
	ctx, cancel := context.WithCancel(context.Background())
	r, err := s.Open(ctx, id, key)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = r.ReadAt(make([]byte, 10), 0)
	wantErr(t, err, context.Canceled)
	// A Get blocked on the network returns when the context ends.
	ctx, cancel = context.WithCancel(context.Background())
	r, err = s.Open(ctx, id, key)
	if err != nil {
		t.Fatal(err)
	}
	r.s = New(cancelling{m})
	errc := make(chan error, 1)
	go func() {
		_, err := r.ReadAt(make([]byte, 10), 0)
		errc <- err
	}()
	cancel()
	wantErr(t, <-errc, context.Canceled)
	var nilCtx context.Context
	_, err = s.Open(nilCtx, id, key)
	wantErr(t, err, ErrInvalidArgument)
}

// A range read over the network fetches only the root, one node per level and the chunks under the
// range, each entry with its kolo-sync inclusion proof.
func TestRemoteRangeRead(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	_, l, alice := storeLog(t)
	lb := NewLogBackend(l)
	p := v0
	p.fanout = 4 // three levels from about 33 chunks
	key := NewKey()
	data := randBytes(17, 40<<20)
	id := mustWrite(t, withParams(lb, p), key, data)

	// The writer's object table, as kolo-files keeps it.
	table := map[Hash]uint64{}
	for h, err := range withParams(lb, p).Objects(ctx, id, key) {
		if err != nil {
			t.Fatal(err)
		}
		if table[h], err = lb.Index(context.Background(), h); err != nil {
			t.Fatal(err)
		}
	}

	srv := kolosync.NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access { return kolosync.Keys })
	if err := srv.Offer(l); err != nil {
		t.Fatal(err)
	}
	addr := serveSync(t, alice, srv)
	conn, err := kolosecure.Dial(ctx, addr, generate(t), alice.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	head, err := kolosync.FetchHead(ctx, conn, alice.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	var fetched atomic.Int64
	fetch := func(ctx context.Context, i uint64) ([]byte, error) {
		f, err := kolosync.Fetch(ctx, conn, head, i, i)
		if err != nil {
			return nil, err
		}
		if len(f) != 1 || f[0].Index != i {
			return nil, fmt.Errorf("fetched %d entries for %d", len(f), i)
		}
		fetched.Add(1)
		return f[0].Data, f[0].Err
	}
	locate := func(h Hash) (uint64, bool) {
		i, ok := table[h]
		return i, ok
	}
	s := withParams(NewRemoteBackend(fetch, locate), p)
	r, err := s.Open(ctx, id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	buf := make([]byte, 10)
	off := int64(30 << 20)
	if _, err := r.ReadAt(buf, off); err != nil || !bytes.Equal(buf, data[off:off+10]) {
		t.Fatalf("range read: %v", err)
	}
	if n := fetched.Load(); n != 4 {
		t.Fatalf("a 10-byte read fetched %d entries of %d, want the root, two nodes and a chunk", n, l.Len())
	}
	// A whole read fetches each object it needs once more at most, and the bytes match.
	got := make([]byte, len(data))
	if _, err := r.ReadAt(got, 0); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("whole read: %v", err)
	}
}
