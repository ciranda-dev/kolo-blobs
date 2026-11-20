package koloblobs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recorder is a Backend that records the order of its Puts and fails when two run at once.
type recorder struct {
	mu       sync.Mutex
	objs     map[Hash][]byte
	order    []Hash
	busy     atomic.Int32
	overlap  atomic.Bool
	putBytes atomic.Int64
	failAt   int           // the Put with this number (from 1) fails; 0 never
	slow     time.Duration // each Put takes this long
	onPut    func(n int)
}

func newRecorder() *recorder { return &recorder{objs: map[Hash][]byte{}} }

func (r *recorder) Get(_ context.Context, h Hash) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o, ok := r.objs[h]; ok {
		return o, nil
	}
	return nil, ErrNotFound
}

var errPut = errors.New("put failed")

func (r *recorder) Put(_ context.Context, h Hash, obj []byte) error {
	if r.busy.Add(1) > 1 {
		r.overlap.Store(true)
	}
	defer r.busy.Add(-1)
	r.mu.Lock()
	r.order = append(r.order, h)
	n := len(r.order)
	r.objs[h] = bytes.Clone(obj)
	r.mu.Unlock()
	r.putBytes.Add(int64(len(obj) - ObjectOverhead))
	if r.onPut != nil {
		r.onPut(n)
	}
	if r.slow > 0 {
		time.Sleep(r.slow)
	}
	if r.failAt == n {
		return errPut
	}
	return nil
}

// smallParams cuts chunks of about 4 KiB, so a few hundred KiB make many chunks and a tall tree.
func smallStore(b Backend, workers int) *Store {
	s := New(b)
	s.p = params{fanout: 4, minChunk: 1 << 10, avgBits: 12, maxChunk: 16 << 10, maxSize: MaxSize}
	s.workers = workers
	return s
}

// The pipeline stores the same objects, in the same order, under the same ID as a Write that does everything in
// turn, for every number of workers, and the blob reads back.
func TestWritePipelineMatchesSerial(t *testing.T) {
	key := Key{9}
	for _, size := range []int{0, 1, 1 << 10, 5 << 10, 64 << 10, 700 << 10, 3 << 20} {
		data := randBytes(61, size)
		serial := newRecorder()
		want, err := smallStore(serial, 1).Write(context.Background(), key, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		for _, workers := range []int{2, 3, 8} {
			got := newRecorder()
			s := smallStore(got, workers)
			id, err := s.Write(context.Background(), key, bytes.NewReader(data))
			if err != nil {
				t.Fatalf("%d bytes, %d workers: %v", size, workers, err)
			}
			if id != want {
				t.Fatalf("%d bytes, %d workers: ID %s, serial %s", size, workers, id, want)
			}
			if len(got.order) != len(serial.order) {
				t.Fatalf("%d bytes, %d workers: %d objects, serial %d", size, workers, len(got.order), len(serial.order))
			}
			for i := range got.order {
				if got.order[i] != serial.order[i] || !bytes.Equal(got.objs[got.order[i]], serial.objs[got.order[i]]) {
					t.Fatalf("%d bytes, %d workers: object %d differs", size, workers, i)
				}
			}
			if got.overlap.Load() {
				t.Fatalf("two Puts ran at once")
			}
			if st := s.Stats(); st.BytesWritten != uint64(size) || st.ObjectsPut != uint64(len(got.order)) {
				t.Fatalf("stats %+v for %d bytes and %d objects", st, size, len(got.order))
			}
			if back := mustRead(t, s, id, key); !bytes.Equal(back, data) {
				t.Fatalf("%d bytes, %d workers: the blob does not read back", size, workers)
			}
		}
	}
}

// With the real parameters the default store, which pipelines, gives the same ID as one worker.
func TestWritePipelineDefaultParams(t *testing.T) {
	key := Key{3}
	data := randBytes(62, 24<<20)
	one := New(newRecorder())
	one.workers = 1
	want := mustWrite(t, one, key, data)
	many := New(newRecorder())
	many.workers = 4
	if got := mustWrite(t, many, key, data); got != want {
		t.Fatalf("ID %s, serial %s", got, want)
	}
}

func goroutinesSettle(t *testing.T, before int) {
	t.Helper()
	for range 100 {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines: %d before, %d after", before, runtime.NumGoroutine())
}

func TestWritePipelineBackendError(t *testing.T) {
	before := runtime.NumGoroutine()
	for _, at := range []int{1, 2, 7, 20} {
		r := newRecorder()
		r.failAt = at
		_, err := smallStore(r, 4).Write(context.Background(), Key{1}, bytes.NewReader(randBytes(63, 400<<10)))
		if !errors.Is(err, errPut) {
			t.Fatalf("Put %d fails: %v", at, err)
		}
		if len(r.order) != at {
			t.Fatalf("Put %d fails but %d objects were put", at, len(r.order))
		}
	}
	goroutinesSettle(t, before)
}

type failingReader struct {
	r io.Reader
	n int
}

var errRead = errors.New("read failed")

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errRead
	}
	n, err := f.r.Read(p[:min(len(p), f.n)])
	f.n -= n
	return n, err
}

func TestWritePipelineSourceError(t *testing.T) {
	before := runtime.NumGoroutine()
	r := newRecorder()
	src := &failingReader{r: bytes.NewReader(randBytes(64, 400<<10)), n: 200 << 10}
	if _, err := smallStore(r, 4).Write(context.Background(), Key{1}, src); !errors.Is(err, errRead) {
		t.Fatalf("source error: %v", err)
	}
	goroutinesSettle(t, before)
}

func TestWritePipelineCancel(t *testing.T) {
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	r := newRecorder()
	r.slow = time.Millisecond
	r.onPut = func(n int) {
		if n == 10 {
			cancel()
		}
	}
	_, err := smallStore(r, 4).Write(ctx, Key{1}, bytes.NewReader(randBytes(65, 4<<20)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if len(r.order) > 10+2*4+2+1 {
		t.Fatalf("%d objects were put after the cancel at 10", len(r.order))
	}
	goroutinesSettle(t, before)
}

// A slow Put does not let the reader run ahead without bound: only the jobs in flight hold chunks.
func TestWritePipelineBoundedMemory(t *testing.T) {
	r := newRecorder()
	r.slow = 200 * time.Microsecond
	s := smallStore(r, 4)
	src := &aheadReader{r: newStream(66, 8<<20), put: &r.putBytes}
	if _, err := s.Write(context.Background(), Key{1}, src); err != nil {
		t.Fatal(err)
	}
	// 10 jobs of at most one chunk, the chunker's own buffer of two, and the reads that fill it.
	if bound := int64(13*s.p.maxChunk + 64<<10); src.peak > bound {
		t.Fatalf("the reader ran %d bytes ahead of the backend, more than %d", src.peak, bound)
	}
	if src.peak == 0 {
		t.Fatal("nothing was measured")
	}
}

// aheadReader tracks the most bytes it has read beyond what the backend has stored.
type aheadReader struct {
	r    io.Reader
	put  *atomic.Int64
	read int64
	peak int64
}

func (a *aheadReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	a.read += int64(n)
	a.peak = max(a.peak, a.read-a.put.Load())
	return n, err
}

func BenchmarkWriteWorkers(b *testing.B) {
	data := randBytes(81, benchSize)
	key := NewKey()
	for _, w := range []int{1, 2, 4, 8} {
		b.Run(string(rune('0'+w))+"workers", func(b *testing.B) {
			s := New(discard{})
			s.workers = w
			b.SetBytes(benchSize)
			for b.Loop() {
				if _, err := s.Write(b.Context(), key, bytes.NewReader(data)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// fixedStore cuts every chunk at 8 KiB, so each job buffer reaches its final size on its first chunk.
func fixedStore(b Backend) *Store {
	s := smallStore(b, 4)
	s.p.minChunk, s.p.maxChunk, s.p.avgBits = 8<<10, 8<<10, 13
	return s
}

// keeper is a Backend that breaks the Put contract on purpose and keeps obj, so a test can see that the buffers of the
// pipeline are cleared when a Write ends.
type keeper struct {
	recorder
	kept    [][]byte
	panicAt int // the Put with this number (from 1) panics with errPut
}

func (k *keeper) Put(ctx context.Context, h Hash, obj []byte) error {
	k.mu.Lock()
	k.kept = append(k.kept, obj)
	n := len(k.kept)
	k.mu.Unlock()
	if n == k.panicAt {
		panic(errPut)
	}
	return nil
}

// allZero reports whether the last seven chunk objects, the buffers of the seven jobs (4 workers and 3), are zero.
// Tree nodes are built elsewhere and are smaller than a chunk.
func (k *keeper) allZero() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	var chunks [][]byte
	for _, o := range k.kept {
		if len(o) > 4<<10 {
			chunks = append(chunks, o)
		}
	}
	for _, o := range chunks[max(0, len(chunks)-7):] {
		if !bytes.Equal(o, make([]byte, len(o))) {
			return false
		}
	}
	return len(chunks) > 0
}

type panicReader struct {
	r io.Reader
	n int
}

func (p *panicReader) Read(b []byte) (int, error) {
	if p.n <= 0 {
		panic(errRead)
	}
	n, err := p.r.Read(b[:min(len(b), p.n)])
	p.n -= n
	return n, err
}

func caught(f func()) (v any) {
	defer func() { v = recover() }()
	f()
	return nil
}

// A panic of the source or of Put reaches the caller of Write, as it does from a Write in turn: no goroutine of the
// pipeline is left, and the buffers that held the file are cleared.
func TestWritePipelinePanics(t *testing.T) {
	before := runtime.NumGoroutine()
	for _, tc := range []struct {
		name string
		run  func(k *keeper)
		want error
	}{
		{"source", func(k *keeper) {
			src := &panicReader{r: bytes.NewReader(randBytes(66, 400<<10)), n: 200 << 10}
			fixedStore(k).Write(context.Background(), Key{1}, src)
		}, errRead},
		{"put", func(k *keeper) {
			k.panicAt = 3
			fixedStore(k).Write(context.Background(), Key{1}, bytes.NewReader(randBytes(67, 400<<10)))
		}, errPut},
	} {
		k := &keeper{recorder: *newRecorder()}
		if v := caught(func() { tc.run(k) }); v != tc.want {
			t.Fatalf("%s: the caller recovered %v, want %v", tc.name, v, tc.want)
		}
		goroutinesSettle(t, before)
		if !k.allZero() {
			t.Fatalf("%s: a buffer of the pipeline kept file content after the panic", tc.name)
		}
	}
}

// gatedReader serves 8 KiB a Read, and from its third Read on waits for gate to close and then a while more, so that a
// failure of the pipeline has happened before the chunk it reads is handed on.
type gatedReader struct {
	r     io.Reader
	gate  chan struct{}
	reads int
}

func (g *gatedReader) Read(b []byte) (int, error) {
	if g.reads++; g.reads >= 3 {
		<-g.gate
		time.Sleep(30 * time.Millisecond)
	}
	return g.r.Read(b[:min(len(b), 8<<10)])
}

// After a failure the reader takes no chunk more: when it comes back from the source to a pipeline that has failed and
// has free jobs, it stops, where select would pick between the two ready channels at random.
func TestWritePipelineStopsReadingAfterAFailure(t *testing.T) {
	want := 0
	for i := range 20 {
		r := newRecorder()
		r.failAt = 1
		gate := make(chan struct{})
		r.onPut = func(int) { close(gate) }
		src := &gatedReader{r: bytes.NewReader(randBytes(68, 2<<20)), gate: gate}
		if _, err := fixedStore(r).Write(context.Background(), Key{1}, src); !errors.Is(err, errPut) {
			t.Fatal(err)
		}
		if i == 0 {
			want = src.reads
		}
		if src.reads != want {
			t.Fatalf("run %d read the source %d times, run 0 read it %d times", i, src.reads, want)
		}
	}
}
