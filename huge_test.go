package koloblobs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const hugeSize = 10 << 30

// regenBackend keeps only the hash, offset and length of each chunk, and builds the object again from the
// generated source when it is read: encryption is deterministic, so the rebuilt object must have the same
// hash. Nodes, a few KiB each, are kept whole.
type regenBackend struct {
	ks  *keys
	src *stream

	mu     sync.Mutex
	nodes  map[Hash][]byte
	chunks map[Hash][2]int64
	next   int64
	pt     []byte
}

func (b *regenBackend) Put(_ context.Context, h Hash, obj []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(obj) <= 32<<10 {
		if _, err := b.ks.open(nil, labelNode, obj); err == nil {
			b.nodes[h] = bytes.Clone(obj)
			return nil
		}
		if _, err := b.ks.open(nil, labelRoot, obj); err == nil {
			b.nodes[h] = bytes.Clone(obj)
			return nil
		}
	}
	n := int64(len(obj) - ObjectOverhead)
	b.chunks[h] = [2]int64{b.next, n}
	b.next += n
	return nil
}

func (b *regenBackend) Get(_ context.Context, h Hash) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if o, ok := b.nodes[h]; ok {
		return o, nil
	}
	c, ok := b.chunks[h]
	if !ok {
		return nil, ErrNotFound
	}
	if cap(b.pt) < int(c[1]) {
		b.pt = make([]byte, MaxChunkSize)
	}
	pt := b.pt[:c[1]]
	b.src.fill(pt, c[0])
	return b.ks.seal(nil, labelChunk, pt)
}

type compare struct {
	src  *stream
	off  int64
	want []byte
}

func (c *compare) Write(p []byte) (int, error) {
	if cap(c.want) < len(p) {
		c.want = make([]byte, len(p))
	}
	w := c.want[:len(p)]
	c.src.fill(w, c.off)
	if !bytes.Equal(p, w) {
		return 0, fmt.Errorf("wrong bytes at offset %d", c.off)
	}
	c.off += int64(len(p))
	return len(p), nil
}

// TestHugeChild writes and reads back the 10 GiB file for TestHugeFileBoundedMemory, and prints the peak
// heap it sampled.
func TestHugeChild(t *testing.T) {
	if os.Getenv("KOLO_BLOBS_HUGE") == "" {
		t.Skip("run by TestHugeFileBoundedMemory")
	}
	key := NewKey()
	ks, err := deriveKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	b := &regenBackend{ks: ks, src: newStream(51, hugeSize), nodes: map[Hash][]byte{}, chunks: map[Hash][2]int64{}}
	var peak uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			peak = max(peak, ms.HeapInuse)
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	})
	start := time.Now()
	s := New(b)
	id, err := s.Write(context.Background(), key, newStream(51, hugeSize))
	if err != nil {
		t.Fatal(err)
	}
	wrote := time.Since(start)
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	if r.root.height != 2 {
		t.Fatalf("height %d, want 2", r.root.height)
	}
	start = time.Now()
	n, err := io.Copy(&compare{src: newStream(51, hugeSize)}, r)
	if err != nil || n != hugeSize {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	read := time.Since(start)
	close(stop)
	wg.Wait()
	fmt.Printf("HUGE heap=%d chunks=%d nodes=%d write=%s read=%s\n", peak, len(b.chunks), len(b.nodes), wrote.Round(time.Millisecond), read.Round(time.Millisecond))
}

// maxRSSBound is the peak resident size a 10 GiB test may reach. The heap bound is the tight one; the resident size
// depends on the allocator and the operating system, so this only proves it is far below the size of the file.
const maxRSSBound = 512 << 20

// A 10 GiB generated file is written and read back, every chunk verified, with a peak heap and resident
// size far below the file and close to a few chunks. The source is generated, so no disk is used.
func TestHugeFileBoundedMemory(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("10 GiB of hashing and encryption; skipped with -short and -race")
	}
	cmd, sc := startChild(t, "TestHugeChild", "KOLO_BLOBS_HUGE=1", "GOMEMLIMIT=64MiB")
	f := waitLine(t, sc, "HUGE")
	for sc.Scan() {
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	var heap uint64
	fmt.Sscanf(f[1], "heap=%d", &heap)
	rss := maxRSS(cmd.ProcessState)
	t.Logf("10 GiB: peak heap %d MiB, peak RSS %d MiB, %s", heap>>20, rss>>20, strings.Join(f[2:], " "))
	if heap > 64<<20 {
		t.Fatalf("peak heap %d bytes", heap)
	}
	if rss != 0 && rss > maxRSSBound {
		t.Fatalf("peak resident size %d bytes", rss)
	}
}
