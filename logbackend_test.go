package koloblobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolostore "github.com/ciranda-dev/kolo-store"
)

func generate(t testing.TB) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func storeLog(t testing.TB) (*kolostore.Store, *kolostore.Log, *koloid.Identity) {
	t.Helper()
	st := kolostore.New(kolostore.NewMemory())
	t.Cleanup(func() { st.Close() })
	owner := generate(t)
	l, err := st.Create(owner)
	if err != nil {
		t.Fatal(err)
	}
	return st, l, owner
}

func TestLogBackendNilContext(t *testing.T) {
	_, l, _ := storeLog(t)
	b := NewLogBackend(l)
	var nilCtx context.Context
	_, err := b.Get(nilCtx, Hash{})
	wantErr(t, err, ErrInvalidArgument)
	_, err = b.Index(nilCtx, Hash{})
	wantErr(t, err, ErrInvalidArgument)
	obj := []byte("an object")
	wantErr(t, b.Put(nilCtx, hashOf(obj), obj), ErrInvalidArgument)
	if l.Len() != 0 {
		t.Fatalf("a Put with a nil context appended %d entries", l.Len())
	}
}

func TestLogBackendRoundTrip(t *testing.T) {
	_, l, _ := storeLog(t)
	b := NewLogBackend(l)
	s := New(b)
	key := NewKey()
	data := randBytes(21, 5<<20)
	id := mustWrite(t, s, key, data)
	n := l.Len()
	if n < 3 {
		t.Fatalf("%d entries for a 5 MiB blob", n)
	}
	if !bytes.Equal(mustRead(t, s, id, key), data) {
		t.Fatal("wrong bytes")
	}
	// Writing it again appends nothing; a fresh backend on the same log indexes it and also appends nothing.
	mustWrite(t, s, key, data)
	mustWrite(t, New(NewLogBackend(l)), key, data)
	if l.Len() != n {
		t.Fatalf("rewrites grew the log from %d to %d entries", n, l.Len())
	}
	if !bytes.Equal(mustRead(t, New(NewLogBackend(l)), id, key), data) {
		t.Fatal("wrong bytes through a fresh backend")
	}
}

// Entries that are not objects, and entries appended by someone else, are indexed and do no harm.
func TestLogBackendSharedLog(t *testing.T) {
	_, l, _ := storeLog(t)
	if _, err := l.Append([]byte("not an object")); err != nil {
		t.Fatal(err)
	}
	b := NewLogBackend(l)
	s := New(b)
	key := NewKey()
	id1 := mustWrite(t, s, key, randBytes(22, 1000))
	if _, err := l.Append([]byte("another")); err != nil {
		t.Fatal(err)
	}
	id2 := mustWrite(t, s, key, randBytes(23, 1000))
	for _, id := range []ID{id1, id2} {
		if len(mustRead(t, New(NewLogBackend(l)), id, key)) != 1000 {
			t.Fatal("wrong size")
		}
	}
	_, err := b.Get(context.Background(), Hash{1})
	wantErr(t, err, ErrNotFound)
}

func TestLogBackendPutChecks(t *testing.T) {
	_, l, _ := storeLog(t)
	b := NewLogBackend(l)
	wantErr(t, b.Put(context.Background(), Hash{}, []byte("x")), ErrInvalidArgument)
	big := make([]byte, MaxObjectSize+1)
	wantErr(t, b.Put(context.Background(), hashOf(big), big), ErrTooLarge)
	if l.Len() != 0 {
		t.Fatal("a refused Put appended")
	}
	max := make([]byte, MaxObjectSize)
	if err := b.Put(context.Background(), hashOf(max), max); err != nil {
		t.Fatal(err)
	}
	var nilB *LogBackend
	wantErr(t, nilB.Put(context.Background(), Hash{}, nil), ErrInvalidArgument)
	_, err := nilB.Get(context.Background(), Hash{})
	wantErr(t, err, ErrInvalidArgument)
	_, err = NewLogBackend(nil).Get(context.Background(), Hash{})
	wantErr(t, err, ErrInvalidArgument)
}

// A replica without entry keys cannot read the objects until the keys arrive; it is read-only.
func TestLogBackendReplica(t *testing.T) {
	_, l, owner := storeLog(t)
	key := NewKey()
	data := randBytes(24, 3<<20)
	id := mustWrite(t, New(NewLogBackend(l)), key, data)

	rs := kolostore.New(kolostore.NewMemory())
	defer rs.Close()
	rep, err := rs.OpenReplica(owner.PublicKey(), l.ID(), l.Header().Encode())
	if err != nil {
		t.Fatal(err)
	}
	head, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	var entries []kololog.Entry
	var keysOf [][]byte
	for i := range l.Len() {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		keysOf = append(keysOf, e.Key)
		e.Key = nil
		entries = append(entries, e)
	}
	if err := rep.Update(head, kololog.ConsistencyProof{}, entries); err != nil {
		t.Fatal(err)
	}
	b := NewLogBackend(rep)
	s := New(b)
	_, err = s.Open(context.Background(), id, key)
	wantErr(t, err, ErrNotFound)
	if len(b.keyless) != len(entries) {
		t.Fatalf("%d keyless entries, want %d", len(b.keyless), len(entries))
	}
	wantErr(t, b.Put(context.Background(), Hash(id), []byte("x")), ErrInvalidArgument)
	obj := []byte("an object")
	wantErr(t, b.Put(context.Background(), hashOf(obj), obj), ErrReadOnly)

	// The keys arrive, as a kolo-sync pull with Keys access gives them: the same backend now reads.
	for i, k := range keysOf {
		if err := rep.AddKey(uint64(i), k); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(mustRead(t, s, id, key), data) {
		t.Fatal("wrong bytes")
	}
	if len(b.keyless) != 0 {
		t.Fatalf("%d keyless entries left", len(b.keyless))
	}
}

func TestLogBackendDeletedEntry(t *testing.T) {
	_, l, _ := storeLog(t)
	key := NewKey()
	data := randBytes(25, 2<<20)
	b := NewLogBackend(l)
	s := New(b)
	id := mustWrite(t, s, key, data)
	// Delete the first chunk after the backend indexed it, then read through a fresh backend too.
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Store{s, New(NewLogBackend(l))} {
		r, err := s.Open(context.Background(), id, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = r.ReadAt(make([]byte, 10), 0)
		wantErr(t, err, ErrNotFound)
		r.Close()
	}
	// Writing the blob again stores the deleted chunk anew and makes it readable.
	mustWrite(t, s, key, data)
	if !bytes.Equal(mustRead(t, s, id, key), data) {
		t.Fatal("wrong bytes after the rewrite")
	}
}

// LogBackend also works on a kolo-log log directly.
func TestLogBackendKoloLog(t *testing.T) {
	l, err := kololog.New(generate(t), kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s := New(NewLogBackend(l))
	key := NewKey()
	data := randBytes(26, 1<<20)
	id := mustWrite(t, s, key, data)
	if !bytes.Equal(mustRead(t, s, id, key), data) {
		t.Fatal("wrong bytes")
	}
}

type fakeLog struct {
	vals      [][]byte
	errs      []error
	appendErr error
	infoErr   error
}

func (f *fakeLog) Len() uint64 { return uint64(len(f.vals)) }

// EntryInfo reports a deleted or keyless entry from its read error; infoErr fails it.
func (f *fakeLog) EntryInfo(i uint64) (kololog.EntryInfo, error) {
	if f.infoErr != nil {
		return kololog.EntryInfo{}, f.infoErr
	}
	return kololog.EntryInfo{Deleted: errors.Is(f.errs[i], kololog.ErrDeleted), Keyed: !errors.Is(f.errs[i], kololog.ErrKeyUnavailable)}, nil
}

func (f *fakeLog) Get(i uint64) ([]byte, error) {
	if f.errs[i] != nil {
		return nil, f.errs[i]
	}
	return f.vals[i], nil
}

func (f *fakeLog) Append(v any) (uint64, error) {
	if f.appendErr != nil {
		return 0, f.appendErr
	}
	f.vals, f.errs = append(f.vals, bytes.Clone(v.([]byte))), append(f.errs, nil)
	return uint64(len(f.vals) - 1), nil
}

func TestLogBackendLogErrors(t *testing.T) {
	boom := errors.New("log closed")
	obj := []byte("object")
	h := hashOf(obj)
	// Reading an entry fails while indexing.
	f := &fakeLog{vals: [][]byte{nil}, errs: []error{boom}}
	wantErr(t, NewLogBackend(f).Put(context.Background(), h, obj), boom)
	_, err := NewLogBackend(f).Get(context.Background(), h)
	wantErr(t, err, boom)
	// Appending fails.
	wantErr(t, NewLogBackend(&fakeLog{appendErr: boom}).Put(context.Background(), h, obj), boom)
	// An indexed entry fails when read again.
	f = &fakeLog{}
	b := NewLogBackend(f)
	if err := b.Put(context.Background(), h, obj); err != nil {
		t.Fatal(err)
	}
	f.errs[0] = boom
	_, err = b.Get(context.Background(), h)
	wantErr(t, err, boom)
	// A keyless entry fails when tried again, and stays to be tried later with the ones after it.
	f = &fakeLog{vals: [][]byte{nil, nil, obj}, errs: []error{kololog.ErrKeyUnavailable, kololog.ErrKeyUnavailable, nil}}
	b = NewLogBackend(f)
	_, err = b.Get(context.Background(), Hash{1})
	wantErr(t, err, ErrNotFound)
	f.errs[0], f.errs[1] = nil, boom
	f.vals[0] = []byte("first")
	_, err = b.Get(context.Background(), Hash{1})
	wantErr(t, err, boom)
	if len(b.keyless) != 1 || b.keyless[0] != 1 {
		t.Fatalf("keyless = %v, want [1]", b.keyless)
	}
	f.errs[1], f.vals[1] = nil, []byte("second")
	for _, v := range [][]byte{[]byte("first"), []byte("second"), obj} {
		if got, err := b.Get(context.Background(), hashOf(v)); err != nil || !bytes.Equal(got, v) {
			t.Fatalf("Get = %q, %v", got, err)
		}
	}
}

// Readers in several goroutines share one LogBackend while a writer appends another blob to the log.
func TestLogBackendConcurrent(t *testing.T) {
	checkGoroutines(t)
	_, l, _ := storeLog(t)
	s := New(NewLogBackend(l))
	key := NewKey()
	data := randBytes(27, 6<<20)
	id := mustWrite(t, s, key, data)
	errs := make(chan error, 5)
	for range 4 {
		go func() {
			r, err := s.Open(context.Background(), id, key)
			if err != nil {
				errs <- err
				return
			}
			defer r.Close()
			b, err := io.ReadAll(r)
			if err == nil && !bytes.Equal(b, data) {
				err = errors.New("wrong bytes")
			}
			errs <- err
		}()
	}
	go func() {
		_, err := s.Write(testCtx(t), NewKey(), bytes.NewReader(randBytes(28, 3<<20)))
		errs <- err
	}()
	for range 5 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

type countLog struct {
	Log
	n atomic.Int64
}

func (c *countLog) Get(i uint64) ([]byte, error) { c.n.Add(1); return c.Log.Get(i) }

func (c *countLog) reads() int { return int(c.n.Load()) }

// A blob whose entries were deleted is stored again by the next Write of the same bytes, and Index does
// not return deleted entries.
func TestRewriteAfterDelete(t *testing.T) {
	_, l, _ := storeLog(t)
	b := NewLogBackend(l)
	s := New(b)
	key := NewKey()
	data := randBytes(3, 2<<20)
	id := mustWrite(t, s, key, data)
	var idx []uint64
	var hashes []Hash
	for h, err := range s.Objects(testCtx(t), id, key) {
		if err != nil {
			t.Fatal(err)
		}
		i, err := b.Index(testCtx(t), h)
		if err != nil {
			t.Fatal(err)
		}
		idx, hashes = append(idx, i), append(hashes, h)
	}
	if err := l.Delete(idx...); err != nil {
		t.Fatal(err)
	}
	for _, h := range hashes {
		_, err := b.Index(testCtx(t), h)
		wantErr(t, err, ErrNotFound)
	}
	n := l.Len()
	if mustWrite(t, s, key, data) != id || l.Len() != n+uint64(len(idx)) {
		t.Fatalf("rewrite appended %d entries, want %d", l.Len()-n, len(idx))
	}
	if !bytes.Equal(mustRead(t, s, id, key), data) {
		t.Fatal("wrong bytes after the rewrite")
	}
}

// The index scan of a new LogBackend skips deleted and keyless entries without reading them, and ends
// with ctx.
func TestLogBackendScan(t *testing.T) {
	_, l, owner := storeLog(t)
	key := NewKey()
	id := mustWrite(t, New(NewLogBackend(l)), key, randBytes(18, 4<<20))
	mustWrite(t, New(NewLogBackend(l)), NewKey(), randBytes(19, 3<<20))
	if err := l.Delete(l.Len()-1, l.Len()-2); err != nil {
		t.Fatal(err)
	}
	c := &countLog{Log: l}
	cb := NewLogBackend(c)
	if _, err := New(cb).Open(testCtx(t), id, key); err != nil {
		t.Fatal(err)
	}
	if len(cb.keyless) != 0 {
		t.Fatalf("deleted entries kept as keyless: %v", cb.keyless)
	}
	if c.reads() != int(l.Len())-2+1 { // every live entry once, then the root again for Open
		t.Fatalf("opening read %d of %d entries, 2 of them deleted", c.reads(), l.Len())
	}

	// A replica without keys reads none.
	rs := kolostore.New(kolostore.NewMemory())
	defer rs.Close()
	rep, err := rs.OpenReplica(owner.PublicKey(), l.ID(), l.Header().Encode())
	if err != nil {
		t.Fatal(err)
	}
	head, _ := l.Head()
	var entries []kololog.Entry
	for i := range l.Len() {
		e, _ := l.Entry(i)
		e.Key = nil
		entries = append(entries, e)
	}
	if err := rep.Update(head, kololog.ConsistencyProof{}, entries); err != nil {
		t.Fatal(err)
	}
	rc := &countLog{Log: rep}
	_, err = New(NewLogBackend(rc)).Open(testCtx(t), id, key)
	wantErr(t, err, ErrNotFound)
	if rc.reads() != 0 {
		t.Fatalf("the scan read %d keyless entries", rc.reads())
	}

	// An ended context stops the scan; a later call goes on from where it stopped.
	b := NewLogBackend(l)
	done, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = b.Get(done, Hash(id))
	wantErr(t, err, context.Canceled)
	wantErr(t, b.Put(done, hashOf([]byte("x")), []byte("x")), context.Canceled)
	if _, err := b.Get(testCtx(t), Hash(id)); err != nil {
		t.Fatal(err)
	}
}

func TestLogBackendEntryInfoError(t *testing.T) {
	boom := errors.New("storage failed")
	obj := []byte("object")
	f := &fakeLog{}
	b := NewLogBackend(f)
	if err := b.Put(testCtx(t), hashOf(obj), obj); err != nil {
		t.Fatal(err)
	}
	f.infoErr = boom
	_, err := b.Get(testCtx(t), hashOf(obj)) // the indexed entry is checked
	wantErr(t, err, boom)
	f.vals, f.errs = append(f.vals, obj), append(f.errs, nil)
	_, err = NewLogBackend(f).Index(testCtx(t), hashOf(obj)) // the scan reads EntryInfo
	wantErr(t, err, boom)
}

// An object held by two entries, of which the one indexed first is deleted, is still found in the other.
func TestDuplicateEntries(t *testing.T) {
	_, l, _ := storeLog(t)
	obj := []byte("an object held twice")
	h := hashOf(obj)
	for range 2 {
		if _, err := l.Append(obj); err != nil {
			t.Fatal(err)
		}
	}
	b := NewLogBackend(l)
	i, err := b.Index(testCtx(t), h)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(i); err != nil {
		t.Fatal(err)
	}
	j, err := b.Index(testCtx(t), h)
	if err != nil || j == i || len(b.index[h]) != 1 {
		t.Fatalf("Index after deleting entry %d = %d, %v, index %v", i, j, err, b.index[h])
	}
	if v, err := b.Get(testCtx(t), h); err != nil || !bytes.Equal(v, obj) {
		t.Fatalf("Get = %v", err)
	}
	if err := l.Delete(j); err != nil {
		t.Fatal(err)
	}
	_, err = b.Index(testCtx(t), h)
	wantErr(t, err, ErrNotFound)
	if _, ok := b.index[h]; ok {
		t.Fatal("an object whose entries are all deleted stays in the index")
	}
	n := l.Len()
	if err := b.Put(testCtx(t), h, obj); err != nil || l.Len() != n+1 {
		t.Fatalf("Put after both were deleted: %v, %d entries added", err, l.Len()-n)
	}
}

// A Write through a LogBackend appends its objects without reading any entry back.
func TestWriteReadsNoEntry(t *testing.T) {
	_, l, _ := storeLog(t)
	c := &countAppender{countLog{Log: l}, l}
	mustWrite(t, New(NewLogBackend(c)), NewKey(), randBytes(42, 6<<20))
	if l.Len() < 3 || c.reads() != 0 {
		t.Fatalf("a write of %d entries read %d", l.Len(), c.reads())
	}
}

// countAppender is a countLog that can also append.
type countAppender struct {
	countLog
	a appender
}

func (c *countAppender) Append(v any) (uint64, error) { return c.a.Append(v) }

// bigFake is a log of n entries: most live, some deleted, some without a key, some repeating an earlier object.
func bigFake(n int) *fakeLog {
	f := &fakeLog{}
	for i := range n {
		v := []byte{byte(i), byte(i >> 8), byte(i >> 16), 1}
		var err error
		switch {
		case i%11 == 3:
			err = kololog.ErrDeleted
		case i%17 == 5:
			err = kololog.ErrKeyUnavailable
		case i%13 == 7 && i > 20:
			v = []byte{byte(i - 13), byte((i - 13) >> 8), byte((i - 13) >> 16), 1} // the object of 13 entries earlier
		}
		f.vals, f.errs = append(f.vals, v), append(f.errs, err)
	}
	return f
}

// The index that the windows of the parallel scan build is the one a scan in turn builds, entry by entry.
func TestLogBackendParallelScanMatchesSerial(t *testing.T) {
	for _, n := range []int{0, 1, 3, 4, 63, 64, 65, 200, 1000} {
		f := bigFake(n)
		par := NewLogBackend(f)
		if err := par.catchUp(context.Background()); err != nil {
			t.Fatal(err)
		}
		ser := NewLogBackend(f)
		for i := range uint64(n) {
			keyless, err := ser.read(context.Background(), i)
			if err != nil {
				t.Fatal(err)
			}
			if keyless {
				ser.keyless = append(ser.keyless, i)
			}
			ser.next++
		}
		if par.next != ser.next || fmt.Sprint(par.keyless) != fmt.Sprint(ser.keyless) || len(par.index) != len(ser.index) {
			t.Fatalf("n=%d: next %d/%d keyless %v/%v index %d/%d", n, par.next, ser.next, par.keyless, ser.keyless, len(par.index), len(ser.index))
		}
		for h, want := range ser.index {
			if fmt.Sprint(par.index[h]) != fmt.Sprint(want) {
				t.Fatalf("n=%d: object %x at %v, want %v", n, h[:4], par.index[h], want)
			}
		}
	}
}

// An error at one entry stops the scan there: every entry before it is indexed, none after, and a retry goes on
// from the entry.
func TestLogBackendParallelScanStopsAtAnError(t *testing.T) {
	boom := errors.New("read failed")
	f := bigFake(300)
	f.errs[150] = boom
	b := NewLogBackend(f)
	err := b.catchUp(context.Background())
	wantErr(t, err, boom)
	if b.next != 150 {
		t.Fatalf("the scan stopped at %d, want 150", b.next)
	}
	f.errs[150] = nil
	if err := b.catchUp(context.Background()); err != nil || b.next != 300 {
		t.Fatalf("after the retry: next %d, %v", b.next, err)
	}
}

// A cancel ends the scan with ctx's error and keeps what was indexed in order.
func TestLogBackendParallelScanCancel(t *testing.T) {
	f := bigFake(5000)
	b := NewLogBackend(f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantErr(t, b.catchUp(ctx), context.Canceled)
	if b.next != 0 || len(b.index) != 0 {
		t.Fatalf("a cancelled scan indexed %d entries, next %d", len(b.index), b.next)
	}
	if err := b.catchUp(context.Background()); err != nil || b.next != 5000 {
		t.Fatalf("next %d, %v", b.next, err)
	}
}

// read indexes entry i in turn, as the windows of a scan must: the reference for TestLogBackendParallelScanMatchesSerial.
func (b *LogBackend) read(ctx context.Context, i uint64) (keyless bool, err error) {
	p := b.probe(ctx, i)
	if p.err != nil {
		return false, p.err
	}
	b.apply(p, i)
	return p.keyless, nil
}

// slowLog is a fakeLog that counts the calls to EntryInfo and Get and makes each Get take a while.
type slowLog struct {
	*fakeLog
	infos, gets atomic.Int64
	wait        time.Duration
}

func (s *slowLog) EntryInfo(i uint64) (kololog.EntryInfo, error) {
	s.infos.Add(1)
	return s.fakeLog.EntryInfo(i)
}

func (s *slowLog) Get(i uint64) ([]byte, error) {
	s.gets.Add(1)
	time.Sleep(s.wait)
	return s.fakeLog.Get(i)
}

// keylessLog is a log of n entries that all lack their key.
func keylessLog(n int) *fakeLog {
	f := &fakeLog{}
	for i := range n {
		f.vals, f.errs = append(f.vals, []byte{byte(i), byte(i >> 8), 1}), append(f.errs, kololog.ErrKeyUnavailable)
	}
	return f
}

// Put does not read the entries that have no key again: a log of them costs a write one read of each, not one on every Put.
func TestLogBackendPutSkipsKeylessEntries(t *testing.T) {
	l := &slowLog{fakeLog: keylessLog(2000)}
	b := NewLogBackend(l)
	obj := []byte("an object")
	if err := b.Put(context.Background(), hashOf(obj), obj); err != nil {
		t.Fatal(err)
	}
	first := l.infos.Load()
	for i := range 20 {
		o := []byte{byte(i), 9, 9}
		if err := b.Put(context.Background(), hashOf(o), o); err != nil {
			t.Fatal(err)
		}
	}
	if more := l.infos.Load() - first; more > 40 {
		t.Fatalf("20 Puts made %d reads of entries, after %d to index the log", more, first)
	}
}

// A lookup that misses reads the keyless entries again, in windows, finds the ones whose key came, and a Get of their
// objects then succeeds; an error leaves the entries it did not reach to be tried again.
func TestLogBackendMissRechecksKeylessEntries(t *testing.T) {
	f := keylessLog(500)
	b := NewLogBackend(f)
	_, err := b.Get(context.Background(), Hash{1})
	wantErr(t, err, ErrNotFound)
	if len(b.keyless) != 500 {
		t.Fatalf("%d keyless entries", len(b.keyless))
	}
	for i := 0; i < 500; i += 2 { // the keys of the even entries arrive
		f.errs[i] = nil
	}
	boom := errors.New("read failed")
	f.errs[301] = boom
	f.errs[300] = boom
	_, err = b.Get(context.Background(), Hash{1})
	wantErr(t, err, boom)
	// Entries 0 to 299 were rechecked in order, the even ones indexed; 300 and everything after it stay.
	if len(b.keyless) != 150+200 || b.keyless[0] != 1 || b.keyless[149] != 299 || b.keyless[150] != 300 {
		t.Fatalf("%d keyless entries, first %d", len(b.keyless), b.keyless[0])
	}
	f.errs[300], f.errs[301] = nil, kololog.ErrKeyUnavailable
	for i := 0; i < 500; i += 2 {
		if got, err := b.Get(context.Background(), hashOf(f.vals[i])); err != nil || !bytes.Equal(got, f.vals[i]) {
			t.Fatalf("entry %d: %q, %v", i, got, err)
		}
	}
	if len(b.keyless) != 250 {
		t.Fatalf("%d keyless entries, want 250", len(b.keyless))
	}
}

// After a read fails, the other readers of the window stop instead of reading, decrypting and hashing the rest.
func TestLogBackendErrorStopsTheWindow(t *testing.T) {
	f := bigFake(catchUpWindow)
	boom := errors.New("read failed")
	f.errs[0] = boom
	l := &slowLog{fakeLog: f, wait: 5 * time.Millisecond}
	err := NewLogBackend(l).catchUp(context.Background())
	wantErr(t, err, boom)
	if n := l.gets.Load(); n > 12 {
		t.Fatalf("%d entries were read after the first failed", n)
	}
}
