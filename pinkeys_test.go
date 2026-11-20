package koloblobs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	"github.com/ciranda-dev/kolo-pin"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// blob is a blob in the content log with its object table, as the writer keeps it.
type blob struct {
	id    ID
	key   Key
	table map[Hash]uint64
}

func (b blob) locate(h Hash) (uint64, bool) {
	i, ok := b.table[h]
	return i, ok
}

// content is a blob in alice's content log, between one written before it and one after it, with the
// writer's object table. The entries of the tested blob are first to last, so first is not 0.
type content struct {
	l           *kolostore.Log
	alice       *koloid.Identity
	key         Key
	id          ID
	data        []byte
	p           params
	table       map[Hash]uint64
	first, last uint64
	before      blob
	after       blob
	head        kololog.VerifiedHead // alice's head after all three blobs, as a reader keeps it
	older       []byte               // an encoded head of alice's from before the last blob
	olderHead   kololog.VerifiedHead // older, verified: a reader that saved its head before the last blob
}

func newContent(t *testing.T) *content {
	t.Helper()
	_, l, alice := storeLog(t)
	c := &content{l: l, alice: alice, key: NewKey(), data: randBytes(43, 40<<20), p: v0}
	c.p.fanout = 4 // three levels from about 33 chunks
	lb := NewLogBackend(l)
	s := withParams(lb, c.p)
	write := func(key Key, data []byte) blob {
		id := mustWrite(t, s, key, data)
		b := blob{id: id, key: key, table: map[Hash]uint64{}}
		for h, err := range s.Objects(testCtx(t), id, key) {
			if err != nil {
				t.Fatal(err)
			}
			if b.table[h], err = lb.Index(testCtx(t), h); err != nil {
				t.Fatal(err)
			}
		}
		return b
	}
	c.before = write(NewKey(), randBytes(44, 3<<20))
	main := write(c.key, c.data)
	c.id, c.table = main.id, main.table
	c.first, c.last = l.Len(), 0
	for _, i := range c.table {
		c.first, c.last = min(c.first, i), max(c.last, i)
	}
	older, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	c.older = older.Encode()
	if c.olderHead, err = kololog.VerifyHead(alice.PublicKey(), l.ID(), older); err != nil {
		t.Fatal(err)
	}
	c.after = write(NewKey(), []byte("another blob"))
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	if c.head, err = kololog.VerifyHead(alice.PublicKey(), l.ID(), h); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *content) locate(h Hash) (uint64, bool) {
	i, ok := c.table[h]
	return i, ok
}

// entryKeys returns the entry keys of the content log, as the owner holds them.
func (c *content) entryKeys(t *testing.T) []kololog.EntryKey {
	t.Helper()
	var keys []kololog.EntryKey
	for i := range c.l.Len() {
		k, err := c.l.Key(i)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	return keys
}

// spanKeys returns the entry keys of the tested blob's span, first to last, as FetchKeys gives them.
func (c *content) spanKeys(t *testing.T) []kololog.EntryKey {
	t.Helper()
	return c.entryKeys(t)[c.first : c.last+1]
}

// heldKeys is the reader's store of the entry keys first and after; it records every copy it hands to kolo-sync. A hostile test
// makes one call, counted from 0, get another entry's key (wrongAt) or none (noneAt).
type heldKeys struct {
	mu              sync.Mutex
	keys            []kololog.EntryKey
	first           uint64
	calls           int
	wrongAt, noneAt int
	given           [][]byte
}

func newHeld(keys []kololog.EntryKey, first uint64) *heldKeys {
	return &heldKeys{keys: keys, first: first, wrongAt: -1, noneAt: -1}
}

func (k *heldKeys) key(i uint64) (kololog.EntryKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := k.calls
	k.calls++
	if n == k.noneAt || i < k.first || i-k.first >= uint64(len(k.keys)) {
		return nil, nil
	}
	j := i - k.first
	if n == k.wrongAt {
		j = (j + 1) % uint64(len(k.keys))
	}
	c := bytes.Clone(k.keys[j])
	k.given = append(k.given, c)
	return c, nil
}

// zeroed reports whether kolo-sync cleared every key copy it was given, and how many there were.
func (k *heldKeys) zeroed() (bool, int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, c := range k.given {
		if !bytes.Equal(c, make([]byte, len(c))) {
			return false, len(k.given)
		}
	}
	return true, len(k.given)
}

// fetchWithKeys is the FetchFunc a reader wires to a ciphertext-only peer: kolo-sync's FetchWithKeys of one
// entry against the head the reader trusts, opened with the key the reader holds. It counts the entries
// fetched.
func fetchWithKeys(conn *kolosecure.Conn, head kololog.VerifiedHead, keys func(uint64) (kololog.EntryKey, error), n *atomic.Int64) FetchFunc {
	return func(ctx context.Context, i uint64) ([]byte, error) {
		f, err := kolosync.FetchWithKeys(ctx, conn, head, i, i, keys)
		if err != nil {
			return nil, err
		}
		n.Add(1)
		return f[0].Data, f[0].Err
	}
}

// Alice pins her content log and gives Bob the entry keys of one blob once; with Alice gone, Bob range-reads
// 10 bytes from the pinning peer, which holds no key, fetching only the root, two nodes and one chunk.
func TestPinRangeReadWithHeldKeys(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	c := newContent(t)
	dir := privateDir(t)
	peer, stopPin := startPin(t, dir)
	capb, err := pin.Issue(c.alice, pin.Capability{Peer: peer.ID, Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pin.Add(ctx, c.alice, peer, c.l, capb); err != nil {
		t.Fatal(err)
	}

	// Bob gets the entry keys from Alice, without ciphertext, then Alice goes away.
	bob := generate(t)
	srv := kolosync.NewServer(func(p, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access {
		if p.Equal(bob.PublicKey()) {
			return kolosync.Keys
		}
		return kolosync.NoAccess
	})
	if err := srv.Offer(c.l); err != nil {
		t.Fatal(err)
	}
	addr, stopAlice := serveSyncStop(t, c.alice, srv)
	t.Cleanup(stopAlice)
	ac, err := kolosecure.Dial(ctx, addr, bob, c.alice.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ah, err := kolosync.FetchHead(ctx, ac, c.alice.PublicKey(), c.l.ID())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kolosync.FetchKeys(ctx, ac, ah, c.first, c.last)
	if err != nil {
		t.Fatal(err)
	}
	saved := ah.Head().Encode() // the reader keeps alice's head with the keys
	ac.Close()
	stopAlice()
	if sent := srv.Stats().BytesSent; sent > 64<<10 {
		t.Fatalf("Alice sent %d bytes for the keys alone", sent)
	}

	pc, err := kolosecure.Dial(ctx, peer.Addr, bob, peer.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dh, err := kololog.DecodeHead(saved)
	if err != nil {
		t.Fatal(err)
	}
	head, err := kololog.VerifyHead(c.alice.PublicKey(), c.l.ID(), dh)
	if err != nil {
		t.Fatal(err)
	}
	held := newHeld(keys, c.first)
	var fetched atomic.Int64
	s := withParams(NewRemoteBackend(fetchWithKeys(pc, head, held.key, &fetched), c.locate), c.p)
	r, err := s.Open(ctx, c.id, c.key)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 10)
	off := int64(30 << 20)
	if _, err := r.ReadAt(buf, off); err != nil || !bytes.Equal(buf, c.data[off:off+10]) {
		t.Fatalf("range read: %v", err)
	}
	if n := fetched.Load(); n != 4 {
		t.Fatalf("a 10-byte read fetched %d entries of %d, want the root, two nodes and a chunk", n, c.l.Len())
	}
	r.Close()
	if ok, n := held.zeroed(); !ok || n != 4 {
		t.Fatalf("%d key copies handed to kolo-sync, cleared after use: %v; want 4 cleared", n, ok)
	}
	// A blob whose entries are outside the span of the keys held is not found.
	other := withParams(NewRemoteBackend(fetchWithKeys(pc, head, held.key, &fetched), c.before.locate), c.p)
	_, err = other.Open(ctx, c.before.id, c.before.key)
	wantErr(t, err, ErrNotFound)
	for _, k := range keys {
		clear(k)
	}

	// The pinning peer's store holds the ciphertext, and no entry key, file key or key derived from it.
	stopPin()
	db, err := kolostore.OpenPebble(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	var dump []byte
	if err := db.Scan(nil, nil, false, 0, func(k, v []byte) bool {
		dump = append(append(dump, k...), v...)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	var files []byte
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) == ".key" {
			return err
		}
		f, err := os.ReadFile(path)
		files = append(files, f...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err := c.l.Entry(c.first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(dump, e.Ciphertext) {
		t.Fatal("the dump does not hold the log's ciphertext, so the scan is wrong")
	}
	for i, k := range secrets(t, c) {
		if len(k) != 0 && (bytes.Contains(dump, k) || bytes.Contains(files, k)) {
			t.Errorf("secret %d found on the pinning peer", i)
		}
	}
}

// pinDouble serves a ciphertext-only replica over the kolo-sync wire, by hand, so a test sees every byte
// the reader sends and can change every answer. It fails the test if it receives anything but the exact
// bytes of a HEAD_REQ for the log or a FETCH_REQ of one entry, so no field can carry key material, if a
// request contains a secret byte string, or if it ever holds an entry key.
type pinDouble struct {
	t       *testing.T
	rep     *kolostore.Replica
	secrets [][]byte
	headReq []byte // the only HEAD_REQ payload a reader of this log sends
	mu      sync.Mutex
	// answer returns the frame to send for a FETCH_REQ of entry start; nil sends the honest answer.
	answer func(start uint64, honest []byte) []byte
	// head returns the frame to send for the HEAD_REQ; nil sends the honest answer.
	head func(honest []byte) []byte
	// errorf reports a request off the list, a secret seen or a key held; t.Errorf unless a test checks the
	// double itself.
	errorf func(format string, args ...any)
}

func newPinDouble(t *testing.T, c *content, secrets [][]byte) *pinDouble {
	t.Helper()
	rs := kolostore.New(kolostore.NewMemory())
	t.Cleanup(func() { rs.Close() })
	rep, err := rs.OpenReplica(c.alice.PublicKey(), c.l.ID(), c.l.Header().Encode())
	if err != nil {
		t.Fatal(err)
	}
	head, err := c.l.Head()
	if err != nil {
		t.Fatal(err)
	}
	var entries []kololog.Entry
	for i := range c.l.Len() {
		e, err := c.l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		e.Key = nil
		entries = append(entries, e)
	}
	if err := rep.Update(head, kololog.ConsistencyProof{}, entries); err != nil {
		t.Fatal(err)
	}
	var e kolocodec.Encoder
	e.PutUvarint(1)
	e.PutUvarint(1)
	e.PutFixed(c.alice.PublicKey())
	id := c.l.ID()
	e.PutFixed(id[:])
	return &pinDouble{t: t, rep: rep, secrets: secrets, headReq: e.Bytes(), errorf: t.Errorf}
}

func (d *pinDouble) scan(b []byte) {
	for i, s := range d.secrets {
		if len(s) != 0 && bytes.Contains(b, s) {
			d.errorf("the pin received secret %d", i)
		}
	}
}

func (d *pinDouble) hooks() (func(uint64, []byte) []byte, func([]byte) []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.answer, d.head
}

// serve answers every stream of every connection on a loopback listener as id until the test ends.
func (d *pinDouble) serve(id *koloid.Identity) string {
	t := d.t
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
				defer conn.Close()
				for {
					st, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					wg.Go(func() {
						defer st.Close()
						d.stream(st)
					})
				}
			})
		}
	})
	t.Cleanup(func() {
		cancel()
		ln.Close()
		wg.Wait()
	})
	return ln.Addr().String()
}

func (d *pinDouble) stream(st *kolotransport.Stream) {
	for {
		var n [4]byte
		if _, err := io.ReadFull(st, n[:]); err != nil {
			return
		}
		size := binary.LittleEndian.Uint32(n[:])
		if size > kolosync.MaxMessageSize {
			d.errorf("a request of %d bytes", size)
			return
		}
		b := make([]byte, size)
		if k, err := io.ReadFull(st, b); err != nil {
			// A partial request is still scanned: key bytes must not reach the pin in any frame.
			d.scan(b[:k])
			d.errorf("a partial request: %d of %d bytes", k, size)
			return
		}
		d.scan(b)
		answer, head := d.hooks()
		var out []byte
		switch {
		case bytes.Equal(b, d.headReq):
			h, err := d.rep.Head()
			if err != nil {
				d.t.Error(err)
				return
			}
			out = headFrame(h.Encode(), d.rep.Header().Encode())
			if head != nil {
				out = head(out)
			}
		default:
			start, size, ok := d.fetchReq(b)
			if !ok {
				d.errorf("the pin got a request off the list: %d bytes", len(b))
				return
			}
			if out = d.fetch(start, start, size); out == nil {
				return
			}
			if answer != nil {
				out = answer(start, out)
			}
		}
		st.Write(out)
		if len(out) < 4 || int(binary.LittleEndian.Uint32(out))+4 != len(out) {
			return // a truncated or oversize frame ends the stream
		}
	}
}

// fetchReq returns the entry and tree size of b if b is exactly a FETCH_REQ of one entry in a tree of at most
// the double's size, as a reader with an older head asks.
func (d *pinDouble) fetchReq(b []byte) (uint64, uint64, bool) {
	dec := kolocodec.NewDecoder(b)
	v, _ := dec.Uvarint()
	typ, _ := dec.Uvarint()
	start, _ := dec.Uvarint()
	end, _ := dec.Uvarint()
	size, err := dec.Uvarint()
	if err != nil || v != 1 || typ != 10 || start != end || size > d.rep.Len() || start >= size {
		return 0, 0, false
	}
	var e kolocodec.Encoder
	for _, x := range []uint64{1, 10, start, end, size} {
		e.PutUvarint(x)
	}
	return start, size, bytes.Equal(e.Bytes(), b)
}

// fetch encodes the FETCH answer for entries start to end of the tree of size entries.
func (d *pinDouble) fetch(start, end, size uint64) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(1)
	e.PutUvarint(11)
	e.PutUvarint(end - start + 1)
	for i := start; i <= end; i++ {
		en, err := d.rep.Entry(i)
		if err != nil {
			d.t.Error(err)
			return nil
		}
		if len(en.Key) != 0 {
			d.errorf("the pin holds the key of entry %d", i)
		}
		p, err := d.rep.InclusionProof(i, size)
		if err != nil {
			d.t.Error(err)
			return nil
		}
		e.PutBytes(en.Record)
		e.PutBytes(en.Ciphertext)
		e.PutBytes(en.Marker)
		e.PutBytes(nil)
		e.PutBytes(p.Encode())
	}
	return frame(e.Bytes())
}

// forkedHead returns the HEAD answer of a pin whose log has the size of c.head and another root, signed by
// alice: she signed two histories.
func forkedHead(t *testing.T, c *content) []byte {
	t.Helper()
	h := c.head.Head()
	h.Root[0] ^= 1
	var e kolocodec.Encoder
	e.PutString(kololog.HeadContext)
	e.PutFixed(h.LogKey)
	e.PutFixed(h.LogID[:])
	e.PutUvarint(h.Size)
	e.PutFixed(h.Root[:])
	var err error
	if h.Signature, err = c.alice.Sign(kololog.HeadContext, e.Bytes()); err != nil {
		t.Fatal(err)
	}
	return headFrame(h.Encode(), c.l.Header().Encode())
}

func headFrame(head, header []byte) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(1)
	e.PutUvarint(5)
	e.PutBytes(head)
	e.PutBytes(header)
	return frame(e.Bytes())
}

func frame(payload []byte) []byte {
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(payload))), payload...)
}

// secrets lists every key of c in play: the file key, its subkeys, gear table and key commitment, and the
// entry keys.
func secrets(t *testing.T, c *content) [][]byte {
	t.Helper()
	ks, err := deriveKeys(c.key)
	if err != nil {
		t.Fatal(err)
	}
	gear := make([]byte, 0, 8*len(ks.gear))
	for _, g := range ks.gear {
		gear = binary.LittleEndian.AppendUint64(gear, g)
	}
	out := [][]byte{c.key[:], ks.macKey[:], ks.enc[:], ks.commit[:], gear}
	for _, k := range c.entryKeys(t) {
		out = append(out, k)
	}
	return out
}

// pinAttack is one way a pin double misbehaves; at counts FETCH answers and keys asked from 0, the root.
type pinAttack struct {
	at              int
	answer          func(start uint64, honest []byte) []byte
	head            func(honest []byte) []byte
	wrongKey, noKey bool
	stall           bool  // the answer never comes, at the HEAD answer if at is -1; the read is cancelled when it is reached
	older           bool  // the reader checks against the head it saved before the last blob
	blob            *blob // the blob to read, from its first bytes; the tested one if nil
}

// pinCase reads 10 bytes of a blob through d changed by h, against alice's head, and returns the bytes
// read and the error. It checks that every key copy handed to kolo-sync was cleared.
func pinCase(t *testing.T, c *content, d *pinDouble, addr string, pid ed25519.PublicKey, h pinAttack) ([]byte, error) {
	t.Helper()
	ctx := testCtx(t)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	var fetches atomic.Int64
	d.mu.Lock()
	d.head = h.head
	if h.stall && h.at < 0 {
		d.head = func(honest []byte) []byte {
			cancel()
			<-release
			return honest
		}
	}
	d.answer = func(start uint64, honest []byte) []byte {
		if int(fetches.Add(1)-1) != h.at {
			return honest
		}
		if h.stall {
			cancel()
			<-release
			return honest
		}
		if h.answer != nil {
			return h.answer(start, honest)
		}
		return honest
	}
	d.mu.Unlock()
	conn, err := kolosecure.Dial(ctx, addr, generate(t), pid, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	keys := c.spanKeys(t)
	defer func() {
		for _, k := range keys {
			clear(k)
		}
	}()
	held := newHeld(keys, c.first)
	if h.wrongKey {
		held.wrongAt = h.at
	}
	if h.noKey {
		held.noneAt = h.at
	}
	defer func() {
		if ok, _ := held.zeroed(); !ok {
			t.Error("a key copy handed to kolo-sync was not cleared after use")
		}
		if h.at >= 0 && int(fetches.Load()) <= h.at {
			t.Errorf("the read stopped after %d answers, before the attack on answer %d", fetches.Load(), h.at)
		}
	}()
	head, b, off := c.head, blob{c.id, c.key, c.table}, int64(30<<20)
	if h.older {
		head = c.olderHead
	}
	if h.blob != nil {
		b, off = *h.blob, 0
	}
	var n atomic.Int64
	s := withParams(NewRemoteBackend(fetchWithKeys(conn, head, held.key, &n), b.locate), c.p)
	r, err := s.Open(ctx, b.id, b.key)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	buf := make([]byte, 10)
	k, err := r.ReadAt(buf, off)
	return buf[:k], err
}

// A pin double that sees every byte Bob sends never receives a key, and an honest one serves the read.
func TestPinDoubleNeverSeesAKey(t *testing.T) {
	checkGoroutines(t)
	c := newContent(t)
	d := newPinDouble(t, c, secrets(t, c))
	pid := generate(t)
	addr := d.serve(pid)
	want := c.data[30<<20 : 30<<20+10]
	got, err := pinCase(t, c, d, addr, pid.PublicKey(), pinAttack{at: -1})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("honest pin: %v", err)
	}
	// A reader whose saved head is older than the pin's reads too: every proof is in its own, smaller tree.
	got, err = pinCase(t, c, d, addr, pid.PublicKey(), pinAttack{at: -1, older: true})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("honest pin, older head: %v", err)
	}
}

// A blob written after the reader's saved head is past it: the read fails before any request, with
// kolosync.ErrInvalidArgument wrapping kololog.ErrOutOfRange, until the reader gets a new head and its keys.
func TestPinNewerVersionNeedsNewHead(t *testing.T) {
	checkGoroutines(t)
	c := newContent(t)
	d := newPinDouble(t, c, secrets(t, c))
	pid := generate(t)
	addr := d.serve(pid)
	_, err := pinCase(t, c, d, addr, pid.PublicKey(), pinAttack{at: -1, older: true, blob: &c.after})
	wantErr(t, err, kolosync.ErrInvalidArgument)
	wantErr(t, err, kololog.ErrOutOfRange)
}

// A hostile pin can stop a read, on the root or on a chunk, but never make it return wrong bytes, and each
// attack ends in the error that names it.
func TestHostilePin(t *testing.T) {
	checkGoroutines(t)
	c := newContent(t)
	d := newPinDouble(t, c, secrets(t, c))
	pid := generate(t)
	addr := d.serve(pid)
	// edit decodes an honest FETCH answer, lets f change its entries and encodes the result.
	edit := func(f func(entries [][5][]byte) [][5][]byte) func(uint64, []byte) []byte {
		return func(_ uint64, honest []byte) []byte {
			dec := kolocodec.NewDecoder(honest[4:])
			dec.Uvarint()
			dec.Uvarint()
			n, _ := dec.Uvarint()
			var entries [][5][]byte
			for range n {
				var e [5][]byte
				for j := range e {
					e[j], _ = dec.Bytes(kolosync.MaxMessageSize)
				}
				entries = append(entries, e)
			}
			entries = f(entries)
			var e kolocodec.Encoder
			e.PutUvarint(1)
			e.PutUvarint(11)
			e.PutUvarint(uint64(len(entries)))
			for _, en := range entries {
				for _, b := range en {
					e.PutBytes(b)
				}
			}
			return frame(e.Bytes())
		}
	}
	set := func(field int, b []byte) func(uint64, []byte) []byte {
		return edit(func(es [][5][]byte) [][5][]byte { es[0][field] = b; return es })
	}
	flip := func(field int) func(uint64, []byte) []byte {
		return edit(func(es [][5][]byte) [][5][]byte {
			es[0][field] = bytes.Clone(es[0][field])
			es[0][field][len(es[0][field])/2] ^= 1
			return es
		})
	}
	_, ol, _ := storeLog(t)
	if _, err := ol.Append([]byte("another log")); err != nil {
		t.Fatal(err)
	}
	oh, err := ol.Head()
	if err != nil {
		t.Fatal(err)
	}
	size := c.l.Len()
	answers := map[string]struct {
		answer func(uint64, []byte) []byte
		want   error
	}{
		"wrong ciphertext":     {flip(1), kolosync.ErrInvalid},
		"wrong proof":          {flip(4), kolosync.ErrInvalid},
		"wrong record":         {flip(0), kolosync.ErrInvalid},
		"forged delete marker": {set(2, bytes.Repeat([]byte{1}, 160)), kolosync.ErrInvalid},
		"a key in the answer":  {set(3, bytes.Repeat([]byte{7}, 32)), kolosync.ErrInvalid},
		"missing entries":      {edit(func([][5][]byte) [][5][]byte { return nil }), kolosync.ErrProtocol},
		"extra entries": {func(start uint64, _ []byte) []byte {
			return d.fetch(start, min(start+1, size-1), size)
		}, kolosync.ErrProtocol},
		"another entry": {func(start uint64, _ []byte) []byte {
			return d.fetch((start+1)%size, (start+1)%size, size)
		}, kolosync.ErrInvalid},
		"not found":          {func(uint64, []byte) []byte { return frame([]byte{1, 9, 1}) }, kolosync.ErrNotFound},
		"truncated response": {func(_ uint64, honest []byte) []byte { return honest[:len(honest)/2] }, kolosync.ErrProtocol},
		"oversize frame": {func(uint64, []byte) []byte {
			return binary.LittleEndian.AppendUint32(nil, kolosync.MaxMessageSize+1)
		}, kolosync.ErrTooLarge},
	}
	type tc struct {
		h    pinAttack
		want error
	}
	cases := map[string]tc{
		"head of another log":     {pinAttack{at: -1, head: func([]byte) []byte { return headFrame(oh.Encode(), ol.Header().Encode()) }}, kolosync.ErrInvalid},
		"an older head":           {pinAttack{at: -1, head: func([]byte) []byte { return headFrame(c.older, c.l.Header().Encode()) }}, kolosync.ErrBehind},
		"garbage head":            {pinAttack{at: -1, head: func([]byte) []byte { return frame([]byte{1, 5, 3, 1, 2, 3}) }}, kolosync.ErrProtocol},
		"same size, other root":   {pinAttack{at: -1, head: func([]byte) []byte { return forkedHead(t, c) }}, kolosync.ErrDiverged},
		"stalled pin at the head": {pinAttack{at: -1, stall: true}, context.Canceled},
	}
	for _, at := range []int{0, 3} {
		where := map[int]string{0: "root", 3: "chunk"}[at]
		for name, a := range answers {
			cases[name+" at the "+where] = tc{pinAttack{at: at, answer: a.answer}, a.want}
		}
		cases["a key that does not match at the "+where] = tc{pinAttack{at: at, wrongKey: true}, kolosync.ErrKeyMismatch}
		cases["no key held at the "+where] = tc{pinAttack{at: at, noKey: true}, ErrNotFound}
		cases["stalled pin at the "+where] = tc{pinAttack{at: at, stall: true}, context.Canceled}
	}
	// One bad key among good ones: the entries before it open, and that read alone fails.
	for _, at := range []int{1, 2} {
		cases[fmt.Sprintf("a key that does not match at node %d", at)] = tc{pinAttack{at: at, wrongKey: true}, kolosync.ErrKeyMismatch}
		cases[fmt.Sprintf("no key held at node %d", at)] = tc{pinAttack{at: at, noKey: true}, ErrNotFound}
	}
	want := c.data[30<<20 : 30<<20+10]
	for name, x := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := pinCase(t, c, d, addr, pid.PublicKey(), x.h)
			if !errors.Is(err, x.want) {
				t.Fatalf("read = %q, %v; want %v", got, err, x.want)
			}
			if x.want != ErrNotFound && errors.Is(err, ErrNotFound) {
				t.Fatalf("read = %v, which is ErrNotFound; want only %v", err, x.want)
			}
			if len(got) != 0 && !bytes.Equal(got, want[:len(got)]) {
				t.Fatalf("wrong bytes returned: %q", got)
			}
		})
	}
}

// The double itself reports a request off the list, a key in a request and a key it holds.
func TestPinDoubleChecks(t *testing.T) {
	checkGoroutines(t)
	c := newContent(t)
	keys := c.entryKeys(t)
	d := newPinDouble(t, c, [][]byte{keys[0]})
	var mu sync.Mutex
	var seen []string
	d.errorf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, fmt.Sprintf(format, args...))
	}
	pid := generate(t)
	addr := d.serve(pid)
	conn, err := kolosecure.Dial(testCtx(t), addr, generate(t), pid.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	send := func(payload []byte) {
		st, err := conn.OpenStream(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		st.Write(frame(payload))
		io.ReadFull(st, make([]byte, 4))
		st.Close()
	}
	var e kolocodec.Encoder
	e.PutUvarint(1)
	e.PutUvarint(1)
	e.PutFixed(c.alice.PublicKey())
	e.PutFixed(keys[0]) // a key where the log ID goes
	send(e.Bytes())
	send(append(bytes.Clone(d.headReq), 0)) // one byte past a HEAD_REQ
	var f kolocodec.Encoder
	for _, x := range []uint64{1, 10, 0, 0, c.l.Len(), 5} { // a FETCH_REQ with a field more
		f.PutUvarint(x)
	}
	send(f.Bytes())
	st, err := conn.OpenStream(testCtx(t)) // a partial frame that holds a key, then the end of the stream
	if err != nil {
		t.Fatal(err)
	}
	st.Write(binary.LittleEndian.AppendUint32(nil, 100))
	st.Write(keys[0])
	st.Close()
	io.ReadFull(st, make([]byte, 1))
	if err := d.rep.AddKey(0, keys[0]); err != nil {
		t.Fatal(err)
	}
	d.fetch(0, 0, c.l.Len())
	mu.Lock()
	defer mu.Unlock()
	count := map[string]int{}
	for _, s := range seen {
		for _, class := range []string{"received secret", "off the list", "partial request", "holds the key"} {
			if strings.Contains(s, class) {
				count[class]++
			}
		}
	}
	want := map[string]int{"received secret": 2, "off the list": 3, "partial request": 1, "holds the key": 1}
	if !maps.Equal(count, want) {
		t.Fatalf("the double reported %v, want %v; reports: %q", count, want, seen)
	}
}
