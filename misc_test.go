package koloblobs

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

func TestStats(t *testing.T) {
	m := newMem()
	s := New(m)
	key := NewKey()
	data := randBytes(71, 5<<20)
	id := mustWrite(t, s, key, data)
	st := s.Stats()
	if st.BytesWritten != uint64(len(data)) || st.ObjectsPut != uint64(m.len()) || st.ObjectsFetched != 0 {
		t.Fatalf("after a write: %+v with %d objects", st, m.len())
	}
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadAt(make([]byte, 100), 10); err != nil {
		t.Fatal(err)
	}
	st = s.Stats()
	if st.BytesRead != 100 || st.ObjectsFetched != 2 || st.Rejected != 0 {
		t.Fatalf("after a 100-byte read: %+v", st)
	}
}

func TestKeyRedacted(t *testing.T) {
	k := Key{0xab, 0xcd, 0xef}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "key", k)
	j, err := json.Marshal(struct{ K Key }{k})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%x %v %+v %#v %s %q %d %X", k, k, k, k, k, k, k, k), fmt.Sprintf("%v", &k), k.String(), buf.String(), string(j)} {
		if strings.Contains(s, "abcdef") || strings.Contains(s, "ABCDEF") || strings.Contains(s, "171") || strings.Contains(s, "0xab") || !strings.Contains(s, "[redacted]") {
			t.Fatalf("key shown: %s", s)
		}
	}
	if a, b := NewKey(), NewKey(); a == b {
		t.Fatal("two equal random keys")
	}
}

func TestHexStrings(t *testing.T) {
	if s := (ID{0xab}).String(); s != "ab"+strings.Repeat("0", 62) {
		t.Fatal(s)
	}
	if s := (Hash{0xab}).String(); s != "ab"+strings.Repeat("0", 62) {
		t.Fatal(s)
	}
}

// The subkeys are the documented HKDF and SHA-256 outputs of the file key.
func TestSubkeys(t *testing.T) {
	key := Key{1, 2, 3}
	ks, err := deriveKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := hkdf.Expand(sha256.New, key[:], "kolo-blobs/content-mac/v0", 32)
	enc, _ := hkdf.Expand(sha256.New, key[:], "kolo-blobs/enc/v0", 32)
	gear, _ := hkdf.Expand(sha256.New, key[:], "kolo-blobs/gear/v0", 2048)
	commit := sha256.Sum256(append([]byte("kolo-blobs/key/v0"), key[:]...))
	if !bytes.Equal(ks.macKey[:], mac) || !bytes.Equal(ks.enc[:], enc) || ks.commit != commit {
		t.Fatal("subkeys differ from their definition")
	}
	for i, g := range ks.gear {
		if g != binary.LittleEndian.Uint64(gear[8*i:]) {
			t.Fatalf("gear word %d differs from its definition", i)
		}
	}
}

// Cut points depend on the key, so equal files under two keys give different chunk sizes.
func TestCutPointsDependOnKey(t *testing.T) {
	data := randBytes(72, 32<<20)
	sizes := func(k Key) []int {
		ks, err := deriveKeys(k)
		if err != nil {
			t.Fatal(err)
		}
		c := newChunker(bytes.NewReader(data), &ks.gear, &v0)
		var out []int
		for {
			b, err := c.next()
			if err != nil {
				t.Fatal(err)
			}
			if b == nil {
				return out
			}
			out = append(out, len(b))
		}
	}
	if slices.Equal(sizes(Key{1}), sizes(Key{2})) {
		t.Fatal("two keys cut the same chunks")
	}
}

// The format is fixed: this key and these bytes always give this ID.
func TestFormatVector(t *testing.T) {
	data := randBytes(73, 3<<20)
	id := mustWrite(t, New(newMem()), Key{7}, data)
	if got := id.String(); got != formatVectorID {
		t.Fatalf("ID %s, want %s", got, formatVectorID)
	}
}

const formatVectorID = "c9490a03447a502f2b8c602d77825a25ba8629f43e0c6c706516dd4a81d1e9da"

// A backend error is named by the store, even one whose text starts with the package prefix; one of the
// package's own sentinels passes as it is.
func TestBackendErrorsAreNamed(t *testing.T) {
	foreign := errors.New("koloblobs: from another package")
	_, err := New(&failing{memBackend: newMem(), get: foreign}).Open(testCtx(t), ID{1}, NewKey())
	wantErr(t, err, foreign)
	if !strings.Contains(err.Error(), "get object") {
		t.Fatalf("Open = %q, want the failing step named", err)
	}
	_, err = New(&failing{memBackend: newMem(), put: foreign}).Write(testCtx(t), NewKey(), strings.NewReader("data"))
	wantErr(t, err, foreign)
	if !strings.Contains(err.Error(), "put object") {
		t.Fatalf("Write = %q, want the failing step named", err)
	}
	_, err = New(&failing{memBackend: newMem(), get: ErrNotFound}).Open(testCtx(t), ID{1}, NewKey())
	if err != ErrNotFound {
		t.Fatalf("Open = %q, want ErrNotFound as it is", err)
	}
}
