package koloblobs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

func privateDir(t testing.TB) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// serveSync serves srv on loopback as id until the test ends, and returns the address.
func serveSync(t testing.TB, id *koloid.Identity, srv *kolosync.Server) string {
	t.Helper()
	addr, stop := serveSyncStop(t, id, srv)
	t.Cleanup(stop)
	return addr
}

// serveSyncStop serves srv on loopback as id, and returns the address and a function that stops it.
func serveSyncStop(t testing.TB, id *koloid.Identity, srv *kolosync.Server) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", id, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			wg.Go(func() {
				_ = srv.Serve(ctx, conn)
				_ = conn.Close()
			})
		}
	})
	var once sync.Once
	return ln.Addr().String(), func() {
		once.Do(func() {
			cancel()
			_ = ln.Close()
			wg.Wait()
		})
	}
}

// pull pulls logID of owner from the peer at addr into rep's store, opening rep if it is nil.
func pull(t testing.TB, ctx context.Context, st *kolostore.Store, rep *kolostore.Replica, addr string, peer, owner ed25519.PublicKey, logID kololog.LogID) *kolostore.Replica {
	t.Helper()
	conn, err := kolosecure.Dial(ctx, addr, generate(t), peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if rep == nil {
		header, err := kolosync.FetchHeader(ctx, conn, owner, logID)
		if err != nil {
			t.Fatal(err)
		}
		if rep, err = st.OpenReplica(owner, logID, header); err != nil {
			t.Fatal(err)
		}
	}
	if err := kolosync.Pull(ctx, conn, rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

// A blob pulled through kolo-sync reads the same through a kolo-store replica on disk.
func TestSyncPebbleReplica(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	_, l, alice := storeLog(t)
	key := NewKey()
	data := randBytes(32, 9<<20)
	id := mustWrite(t, New(NewLogBackend(l)), key, data)
	srv := kolosync.NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access { return kolosync.Keys })
	if err := srv.Offer(l); err != nil {
		t.Fatal(err)
	}
	addr := serveSync(t, alice, srv)
	db, err := kolostore.OpenPebble(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	st := kolostore.New(db)
	defer st.Close()
	rep := pull(t, ctx, st, nil, addr, alice.PublicKey(), alice.PublicKey(), l.ID())
	r, err := New(NewLogBackend(rep)).Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read %d bytes, %v", len(got), err)
	}
}
