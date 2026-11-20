package koloblobs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

const resumeSize = 40 << 20

var resumeKey = Key{1, 2, 3}

// countingBackend prints PUT after every object a LogBackend appends, so the parent knows when to kill.
type countingBackend struct {
	*LogBackend
	l    Log
	puts int
}

func (c *countingBackend) Put(ctx context.Context, h Hash, obj []byte) error {
	n := c.l.Len()
	if err := c.LogBackend.Put(ctx, h, obj); err != nil {
		return err
	}
	if c.l.Len() > n {
		c.puts++
		fmt.Printf("PUT %d\n", c.puts)
	}
	return nil
}

// TestWriteChild is the writer process that TestKillWriteResume kills: it writes the resume stream into a
// log on disk, opening the log if a killed run created it.
func TestWriteChild(t *testing.T) {
	dir := os.Getenv("KOLO_BLOBS_WRITE_DIR")
	if dir == "" {
		t.Skip("run by TestKillWriteResume")
	}
	keyPath := filepath.Join(dir, "owner.key")
	owner, err := koloid.Load(keyPath)
	if os.IsNotExist(err) {
		if owner, err = koloid.Generate(); err == nil {
			err = owner.SaveNew(keyPath)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	db, err := kolostore.OpenPebble(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	st := kolostore.New(db)
	defer st.Close()
	var l *kolostore.Log
	ids, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 1 {
		l, err = st.Open(owner, ids[0])
	} else {
		l, err = st.Create(owner)
	}
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("START %d\n", l.Len())
	b := &countingBackend{LogBackend: NewLogBackend(l), l: l}
	id, err := New(b).Write(context.Background(), resumeKey, newStream(41, resumeSize))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("ID %s %d %d\n", id, b.puts, l.Len())
}

func startChild(t *testing.T, test string, env ...string) (*exec.Cmd, *bufio.Scanner) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd, bufio.NewScanner(out)
}

// waitLine reads lines until one starts with prefix and returns its fields.
func waitLine(t *testing.T, sc *bufio.Scanner, prefix string) []string {
	t.Helper()
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) > 0 && f[0] == prefix {
			return f
		}
	}
	t.Fatalf("child ended without a %s line", prefix)
	return nil
}

func kill(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
}

// A writer killed twice part way through, then run to its end, keeps every object it reported stored,
// stores each object once, gives the ID of an uninterrupted write, and its blob reads back.
func TestKillWriteResume(t *testing.T) {
	m := newMem()
	want, err := New(m).Write(testCtx(t), resumeKey, newStream(41, resumeSize))
	if err != nil {
		t.Fatal(err)
	}
	dir := privateDir(t)
	env := "KOLO_BLOBS_WRITE_DIR=" + dir
	held := 0
	for _, at := range []int{5, 11} {
		cmd, sc := startChild(t, "TestWriteChild", env)
		var start int
		fmt.Sscan(waitLine(t, sc, "START")[1], &start)
		if start < held {
			t.Fatalf("the log holds %d entries after a kill, but %d were reported stored", start, held)
		}
		for f := waitLine(t, sc, "PUT"); f[1] != fmt.Sprint(at); f = waitLine(t, sc, "PUT") {
		}
		kill(t, cmd)
		held = start + at
	}
	_, sc := startChild(t, "TestWriteChild", env)
	var start int
	fmt.Sscan(waitLine(t, sc, "START")[1], &start)
	if start < held {
		t.Fatalf("the log holds %d entries after a kill, but %d were reported stored", start, held)
	}
	f := waitLine(t, sc, "ID")
	for sc.Scan() {
	}
	if f[1] != want.String() {
		t.Fatalf("resumed write gave ID %s, want %s", f[1], want)
	}
	if f[2] != fmt.Sprint(m.len()-start) || f[3] != fmt.Sprint(m.len()) {
		t.Fatalf("resumed write appended %s objects to reach %s, want %d to reach %d", f[2], f[3], m.len()-start, m.len())
	}

	db, err := kolostore.OpenPebble(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	st := kolostore.New(db)
	defer st.Close()
	owner, err := koloid.Load(filepath.Join(dir, "owner.key"))
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := st.List()
	l, err := st.Open(owner, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(NewLogBackend(l)).Open(context.Background(), want, resumeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !sameAsStream(t, r, newStream(41, resumeSize)) {
		t.Fatal("the resumed blob reads other bytes")
	}
}

func sameAsStream(t *testing.T, r io.Reader, s *stream) bool {
	t.Helper()
	a, b := sha256.New(), sha256.New()
	if _, err := io.Copy(a, r); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(b, s); err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(a.Sum(nil), b.Sum(nil))
}

// TestPullChild is the reader process that TestKillPullResume kills: it pulls a log into a replica on disk,
// then reads the blob and prints its SHA-256.
func TestPullChild(t *testing.T) {
	dir := os.Getenv("KOLO_BLOBS_PULL_DIR")
	if dir == "" {
		t.Skip("run by TestKillPullResume")
	}
	f := strings.Fields(os.Getenv("KOLO_BLOBS_PULL_ARGS"))
	addr := f[0]
	peer, _ := hex.DecodeString(f[1])
	var logID kololog.LogID
	var id ID
	lb, _ := hex.DecodeString(f[2])
	ib, _ := hex.DecodeString(f[3])
	copy(logID[:], lb)
	copy(id[:], ib)
	db, err := kolostore.OpenPebble(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	st := kolostore.New(db)
	defer st.Close()
	ctx := testCtx(t)
	conn, err := kolosecure.Dial(ctx, addr, generate(t), peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	header, err := kolosync.FetchHeader(ctx, conn, peer, logID)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := st.OpenReplica(peer, logID, header)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("START %d\n", rep.Len())
	if err := kolosync.Pull(ctx, conn, rep); err != nil {
		t.Fatal(err)
	}
	r, err := New(NewLogBackend(rep)).Open(context.Background(), id, resumeKey)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("DONE %x %d\n", h.Sum(nil), rep.Len())
}

// watched serves a log and closes reached when the puller reads entry index.
type watched struct {
	kolosync.Source
	index   uint64
	once    sync.Once
	reached chan struct{}
}

func (w *watched) Entry(i uint64) (kololog.Entry, error) {
	if i == w.index {
		w.once.Do(func() { close(w.reached) })
	}
	return w.Source.Entry(i)
}

// A reader killed in the middle of pulling a blob's log resumes the pull from what it stored, and reads
// the whole blob.
func TestKillPullResume(t *testing.T) {
	checkGoroutines(t)
	_, l, alice := storeLog(t)
	id, err := New(NewLogBackend(l)).Write(testCtx(t), resumeKey, newStream(42, 30<<20))
	if err != nil {
		t.Fatal(err)
	}
	src := &watched{Source: l, index: l.Len() / 2, reached: make(chan struct{})}
	srv := kolosync.NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access { return kolosync.Keys })
	if err := srv.Offer(l); err != nil {
		t.Fatal(err)
	}
	addr := serveSync(t, alice, srv)
	// The bytes of one whole pull, for comparison with the resumed one.
	before := srv.Stats().BytesSent
	ms := kolostore.New(kolostore.NewMemory())
	defer ms.Close()
	pull(t, testCtx(t), ms, nil, addr, alice.PublicKey(), alice.PublicKey(), l.ID())
	whole := srv.Stats().BytesSent - before
	if err := srv.Offer(src); err != nil {
		t.Fatal(err)
	}
	dir := privateDir(t)
	env := []string{"KOLO_BLOBS_PULL_DIR=" + dir, fmt.Sprintf("KOLO_BLOBS_PULL_ARGS=%s %x %s %s", addr, []byte(alice.PublicKey()), l.ID(), id)}

	cmd, sc := startChild(t, "TestPullChild", env...)
	waitLine(t, sc, "START")
	<-src.reached
	kill(t, cmd)
	full := srv.Stats().BytesSent

	_, sc = startChild(t, "TestPullChild", env...)
	start := waitLine(t, sc, "START")
	var held uint64
	fmt.Sscan(start[1], &held)
	if held == 0 || held >= l.Len() {
		t.Fatalf("the killed pull kept %d of %d entries", held, l.Len())
	}
	done := waitLine(t, sc, "DONE")
	for sc.Scan() {
	}
	h := sha256.New()
	if _, err := io.Copy(h, newStream(42, 30<<20)); err != nil {
		t.Fatal(err)
	}
	if done[1] != hex.EncodeToString(h.Sum(nil)) || done[2] != fmt.Sprint(l.Len()) {
		t.Fatalf("resumed pull read %s with %s entries", done[1], done[2])
	}
	// The resumed pull did not fetch again the entries the killed one had stored.
	var heldBytes uint64
	for i := range held {
		e, _ := l.Entry(i)
		heldBytes += uint64(len(e.Ciphertext))
	}
	if second := srv.Stats().BytesSent - full; second > whole-heldBytes/2 {
		t.Fatalf("the resumed pull sent %d bytes, a whole one %d, with %d bytes held", second, whole, heldBytes)
	}
}
