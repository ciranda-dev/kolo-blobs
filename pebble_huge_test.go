package koloblobs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	kolostore "github.com/ciranda-dev/kolo-store"
)

// TestPebbleHugeChild writes the generated file into a kolo-store log on Pebble, closes the store, opens
// it again and reads the blob back, printing the peak heap it sampled.
func TestPebbleHugeChild(t *testing.T) {
	size, _ := strconv.ParseInt(os.Getenv("KOLO_BLOBS_PEBBLE_SIZE"), 10, 64)
	dir := os.Getenv("KOLO_BLOBS_PEBBLE_DIR")
	if dir == "" || size <= 0 {
		t.Skip("run by TestPebbleHugeFileBoundedMemory")
	}
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
	ctx := context.Background()
	key := Key{8}
	owner := generate(t)
	db, err := kolostore.OpenPebble(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	st := kolostore.New(db)
	l, err := st.Create(owner)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	id, err := New(NewLogBackend(l)).Write(ctx, key, newStream(52, size))
	if err != nil {
		t.Fatal(err)
	}
	wrote := time.Since(start)
	logID := l.ID()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	start = time.Now()
	if db, err = kolostore.OpenPebble(filepath.Join(dir, "store")); err != nil {
		t.Fatal(err)
	}
	st = kolostore.New(db)
	defer st.Close()
	if l, err = st.Open(owner, logID); err != nil {
		t.Fatal(err)
	}
	r, err := New(NewLogBackend(l)).Open(ctx, id, key)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(&compare{src: newStream(52, size)}, r)
	if err != nil || n != size {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	read := time.Since(start)
	close(stop)
	wg.Wait()
	fmt.Printf("PEBBLE heap=%d entries=%d write=%s read=%s\n", peak, l.Len(), wrote.Round(time.Millisecond), read.Round(time.Millisecond))
}

// A 10 GiB file written into a kolo-store log on Pebble and read back after the store is opened again
// keeps the heap and resident size near a few chunks: the log reads entries from disk on demand.
func TestPebbleHugeFileBoundedMemory(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("writes and reads 10 GiB on disk; skipped with -short and -race")
	}
	dir := privateDir(t)
	cmd, sc := startChild(t, "TestPebbleHugeChild", "KOLO_BLOBS_PEBBLE_DIR="+dir, fmt.Sprintf("KOLO_BLOBS_PEBBLE_SIZE=%d", int64(hugeSize)), "GOMEMLIMIT=64MiB")
	f := waitLine(t, sc, "PEBBLE")
	for sc.Scan() {
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	var heap uint64
	fmt.Sscanf(f[1], "heap=%d", &heap)
	rss := maxRSS(cmd.ProcessState)
	t.Logf("10 GiB through Pebble: peak heap %d MiB, peak RSS %d MiB, %s", heap>>20, rss>>20, strings.Join(f[2:], " "))
	if heap > 128<<20 {
		t.Fatalf("peak heap %d bytes", heap)
	}
	if rss != 0 && rss > maxRSSBound {
		t.Fatalf("peak resident size %d bytes", rss)
	}
}
