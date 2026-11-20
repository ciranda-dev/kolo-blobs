package koloblobs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	"github.com/ciranda-dev/kolo-pin"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// startPin runs a pinning peer on loopback with its data in dir, and returns it and a stop function.
func startPin(t testing.TB, dir string) (pin.Peer, func()) {
	t.Helper()
	id, err := pin.LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", id, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- pin.Serve(ctx, ln, pin.Options{Dir: dir}) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("pin.Serve: %v", err)
				}
			case <-time.After(20 * time.Second):
				t.Error("pin.Serve did not return")
			}
			_ = ln.Close()
		})
	}
	t.Cleanup(stop)
	return pin.Peer{ID: id.PublicKey(), Addr: ln.Addr().String()}, stop
}

// A blob stored on a pinning peer is fetched from it by another device, which reads it once alice's
// device gives it the entry keys; the pinning peer's store holds neither key nor plaintext.
func TestPinStoreAndFetch(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	dir := privateDir(t)
	peer, stopPin := startPin(t, dir)

	// Alice writes a blob whose first chunk is a full MaxChunkSize, so one entry is the largest that syncs.
	key := zeroKey(t)
	data := append(make([]byte, MaxChunkSize), randBytes(31, 6<<20)...)
	_, l, alice := storeLog(t)
	id := mustWrite(t, New(NewLogBackend(l)), key, data)
	largest := false
	for i := range l.Len() {
		v, _ := l.Get(i)
		largest = largest || len(v) == MaxObjectSize
	}
	if !largest {
		t.Fatal("no entry of MaxObjectSize")
	}
	capb, err := pin.Issue(alice, pin.Capability{Peer: peer.ID, Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	info, err := pin.Add(ctx, alice, peer, l, capb)
	if err != nil || info.Entries != l.Len() {
		t.Fatalf("pin.Add = %+v, %v", info, err)
	}

	// Bob's device pulls the ciphertext from the pinning peer: without entry keys it cannot read the blob.
	bs := kolostore.New(kolostore.NewMemory())
	defer bs.Close()
	rep := pull(t, ctx, bs, nil, peer.Addr, peer.ID, alice.PublicKey(), l.ID())
	if rep.Len() != l.Len() {
		t.Fatalf("pulled %d of %d entries", rep.Len(), l.Len())
	}
	bob := New(NewLogBackend(rep))
	_, err = bob.Open(context.Background(), id, key)
	wantErr(t, err, ErrNotFound)

	// Alice's device gives bob the entry keys; only the keys travel, the ciphertext is already there.
	srv := kolosync.NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access { return kolosync.Keys })
	if err := srv.Offer(l); err != nil {
		t.Fatal(err)
	}
	addr := serveSync(t, alice, srv)
	pull(t, ctx, bs, rep, addr, alice.PublicKey(), alice.PublicKey(), l.ID())
	if sent := srv.Stats().BytesSent; sent > uint64(len(data))/10 {
		t.Fatalf("the key pull sent %d bytes for a %d-byte blob", sent, len(data))
	}
	if !bytes.Equal(mustRead(t, bob, id, key), data) {
		t.Fatal("bob read other bytes")
	}
	r, err := bob.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1000)
	if _, err := r.ReadAt(b, MaxChunkSize-500); err != nil || !bytes.Equal(b, data[MaxChunkSize-500:MaxChunkSize+500]) {
		t.Fatalf("range read across chunks: %v", err)
	}
	r.Close()

	// What must never be on the pinning peer: the file key, its subkeys, every entry key, the blob's own
	// objects (they are stored only inside kolo-log ciphertext) and the plaintext.
	ks, _ := deriveKeys(key)
	secrets := [][]byte{key[:], ks.macKey[:], ks.enc[:], ks.commit[:], id[:]}
	var ciphertext []byte
	for i := range l.Len() {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, e.Key)
		v, _ := l.Get(i)
		secrets = append(secrets, v[:32], v[len(v)-32:])
		ciphertext = e.Ciphertext
	}
	for off := len(data) - 1; off > MaxChunkSize; off -= 300 << 10 {
		secrets = append(secrets, data[off-32:off])
	}
	stopPin()
	var dump, files []byte
	db, err := kolostore.OpenPebble(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Scan(nil, nil, false, 0, func(k, v []byte) bool {
		dump = append(append(dump, k...), v...)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(dump, ciphertext) {
		t.Fatal("the dump does not hold the log's ciphertext, so the scan is wrong")
	}
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == "identity.key" {
			return err
		}
		f, err := os.ReadFile(path)
		files = append(files, f...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range secrets {
		if bytes.Contains(dump, s) || bytes.Contains(files, s) {
			t.Errorf("secret %d found on the pinning peer", i)
		}
	}
}
