package koloblobs

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type memBackend struct {
	mu   sync.Mutex
	objs map[Hash][]byte
	gets map[Hash]int
	puts int
}

func newMem() *memBackend { return &memBackend{objs: map[Hash][]byte{}, gets: map[Hash]int{}} }

func (m *memBackend) Get(_ context.Context, h Hash) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets[h]++
	o, ok := m.objs[h]
	if !ok {
		return nil, ErrNotFound
	}
	return o, nil
}

func (m *memBackend) Put(_ context.Context, h Hash, obj []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if _, ok := m.objs[h]; !ok {
		m.objs[h] = bytes.Clone(obj)
	}
	return nil
}

func (m *memBackend) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.objs)
}

func (m *memBackend) totalGets() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.gets {
		n += c
	}
	return n
}

func (m *memBackend) resetGets() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets = map[Hash]int{}
}

// stream is a seekable pseudo-random byte source: the AES-CTR keystream of a seed, so any range can be
// generated again without storing it.
type stream struct {
	block cipher.Block
	size  int64
	pos   int64
}

func newStream(seed byte, size int64) *stream {
	k := make([]byte, 32)
	k[0] = seed
	b, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}
	return &stream{block: b, size: size}
}

func (s *stream) fill(p []byte, off int64) {
	clear(p)
	var iv [16]byte
	binary.BigEndian.PutUint64(iv[8:], uint64(off/16))
	ctr := cipher.NewCTR(s.block, iv[:])
	skip := int(off % 16)
	if skip > 0 {
		var junk [16]byte
		ctr.XORKeyStream(junk[:skip], junk[:skip])
	}
	ctr.XORKeyStream(p, p)
}

func (s *stream) Read(p []byte) (int, error) {
	if s.pos >= s.size {
		return 0, io.EOF
	}
	if int64(len(p)) > s.size-s.pos {
		p = p[:s.size-s.pos]
	}
	s.fill(p, s.pos)
	s.pos += int64(len(p))
	return len(p), nil
}

func randBytes(seed byte, n int) []byte {
	b := make([]byte, n)
	newStream(seed, int64(n)).fill(b, 0)
	return b
}

func testCtx(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func mustWrite(t testing.TB, s *Store, key Key, data []byte) ID {
	t.Helper()
	id, err := s.Write(testCtx(t), key, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustRead(t testing.TB, s *Store, id ID, key Key) []byte {
	t.Helper()
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) != r.Size() {
		t.Fatalf("read %d bytes of a %d-byte blob", len(b), r.Size())
	}
	return b
}

// zeroKey returns a key under which a run of zero bytes has no cut point, so zeros make chunks of
// exactly MaxChunkSize.
func zeroKey(t testing.TB) Key {
	t.Helper()
	for range 100 {
		k := NewKey()
		ks, err := deriveKeys(k)
		if err != nil {
			t.Fatal(err)
		}
		c := newChunker(nil, &ks.gear, &v0)
		// After 64 zeros the gear hash is constant: h = sum of gear[0] << i for i < 64.
		var h uint64
		for range 64 {
			h = h<<1 + ks.gear[0]
		}
		ok := h&c.maskS != 0 && h&c.maskL != 0
		var prev uint64
		for range 63 { // the first 63 hashes after the minimum
			prev = prev<<1 + ks.gear[0]
			if prev&c.maskS == 0 {
				ok = false
			}
		}
		if ok {
			return k
		}
	}
	t.Fatal("no key without a cut point in zeros")
	return Key{}
}

// sealed returns the object of plaintext p under key and label, for building hostile trees.
func sealed(t testing.TB, key Key, label string, p []byte) []byte {
	t.Helper()
	ks, err := deriveKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	o, err := ks.seal(nil, label, p)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func put(t testing.TB, m *memBackend, obj []byte) Hash {
	t.Helper()
	h := hashOf(obj)
	if err := m.Put(context.Background(), h, obj); err != nil {
		t.Fatal(err)
	}
	return h
}

// checkGoroutines fails the test if goroutines started after it are still running after the cleanups.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var leaked []string
			for id, stack := range goroutines() {
				if _, ok := before[id]; !ok {
					leaked = append(leaked, stack)
				}
			}
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines leaked:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := make(map[string]string)
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if id, _, ok := strings.Cut(strings.TrimPrefix(stack, "goroutine "), " "); ok {
			out[id] = stack
		}
	}
	return out
}

func wantErr(t testing.TB, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want %v", err, target)
	}
}

func hashOf(obj []byte) Hash { return Hash(sha256.Sum256(obj)) }
