package koloblobs

import (
	"bytes"
	"context"
	"io"
	"math/rand/v2"
	"testing"

	kolostore "github.com/ciranda-dev/kolo-store"
)

const benchSize = 256 << 20

type discard struct{}

func (discard) Get(context.Context, Hash) ([]byte, error) { return nil, ErrNotFound }
func (discard) Put(context.Context, Hash, []byte) error   { return nil }

// BenchmarkWrite measures chunking, encryption and tree building, with a backend that drops objects.
func BenchmarkWrite(b *testing.B) {
	data := randBytes(81, benchSize)
	s := New(discard{})
	key := NewKey()
	b.SetBytes(benchSize)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := s.Write(b.Context(), key, bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRead measures a sequential read with every object verified, from memory.
func BenchmarkRead(b *testing.B) {
	data := randBytes(82, benchSize)
	m := newMem()
	s := New(m)
	key := NewKey()
	id := mustWrite(b, s, key, data)
	b.SetBytes(benchSize)
	b.ReportAllocs()
	for b.Loop() {
		r, err := s.Open(context.Background(), id, key)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			b.Fatal(err)
		}
		r.Close()
	}
	b.ReportMetric(float64(storedBytes(m))/benchSize*100-100, "overhead%")
}

// BenchmarkReadAtRandom measures 4 KiB reads at random offsets: each fetches and verifies a whole chunk.
func BenchmarkReadAtRandom(b *testing.B) {
	data := randBytes(83, benchSize)
	s := New(newMem())
	key := NewKey()
	id := mustWrite(b, s, key, data)
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	rng := rand.New(rand.NewPCG(1, 2))
	buf := make([]byte, 4096)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := r.ReadAt(buf, rng.Int64N(benchSize-4096)); err != nil {
			b.Fatal(err)
		}
	}
}

func storedBytes(m *memBackend) int {
	n := 0
	for _, o := range m.objs {
		n += len(o)
	}
	return n
}

// BenchmarkLogBackendWrite measures a write into a kolo-store log, in memory and on disk with Pebble,
// where each entry is signed and synced; overhead% is the kolo-log ciphertext over the plaintext.
func BenchmarkLogBackendWrite(b *testing.B) {
	data := randBytes(84, 64<<20)
	for _, disk := range []bool{false, true} {
		name := "memory"
		if disk {
			name = "pebble"
		}
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			var stored int
			for b.Loop() {
				b.StopTimer()
				be := kolostore.NewMemory()
				if disk {
					var err error
					if be, err = kolostore.OpenPebble(privateDir(b)); err != nil {
						b.Fatal(err)
					}
				}
				st := kolostore.New(be)
				l, err := st.Create(generate(b))
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if _, err := New(NewLogBackend(l)).Write(b.Context(), NewKey(), bytes.NewReader(data)); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				stored = 0
				for i := range l.Len() {
					e, _ := l.Entry(i)
					stored += len(e.Ciphertext)
				}
				st.Close()
				b.StartTimer()
			}
			b.ReportMetric(float64(stored)/float64(len(data))*100-100, "overhead%")
		})
	}
}

// BenchmarkChunker measures content-defined chunking alone.
func BenchmarkChunker(b *testing.B) {
	data := randBytes(85, benchSize)
	ks, err := deriveKeys(NewKey())
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(benchSize)
	for b.Loop() {
		c := newChunker(bytes.NewReader(data), &ks.gear, &v0)
		for {
			ch, err := c.next()
			if err != nil {
				b.Fatal(err)
			}
			if ch == nil {
				break
			}
		}
	}
}
