package koloblobs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

var labels = []string{labelChunk, labelNode, labelRoot}

// The content MAC is HMAC-SHA256 over the label's length, the label and the plaintext, stored as the
// object's first 32 bytes.
func TestContentMAC(t *testing.T) {
	ks, err := deriveKeys(Key{4})
	if err != nil {
		t.Fatal(err)
	}
	p := []byte("some plaintext")
	for _, l := range labels {
		m := hmac.New(sha256.New, ks.macKey[:])
		m.Write(binary.AppendUvarint(nil, uint64(len(l))))
		m.Write([]byte(l))
		m.Write(p)
		obj, err := ks.seal(nil, l, p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(obj[:32], m.Sum(nil)) || len(obj) != len(p)+ObjectOverhead {
			t.Fatalf("%s: object does not start with the content MAC", l)
		}
	}
}

// The labels are distinct and prefix-free, and an object of one type never opens as another.
func TestLabelsSeparateTypes(t *testing.T) {
	for i, a := range labels {
		for j, b := range labels {
			if i != j && strings.HasPrefix(a, b) {
				t.Fatalf("%q is a prefix of %q", b, a)
			}
		}
	}
	ks, err := deriveKeys(Key{5})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range labels {
		obj, err := ks.seal(nil, a, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range labels {
			_, err := ks.open(nil, b, obj)
			if (a == b) != (err == nil) {
				t.Fatalf("object sealed as %s opened as %s: %v", a, b, err)
			}
		}
	}
}

// An object whose stored content MAC is not the one of its plaintext is refused, for every object type,
// even though GCM accepts it.
func TestNonCanonicalMACRefused(t *testing.T) {
	h := newHostile(t)
	forge := func(label string, p []byte) Hash {
		s := bytes.Repeat([]byte{7}, 32)
		a, err := h.ks.objectAEAD(s)
		if err != nil {
			t.Fatal(err)
		}
		return put(t, h.m, a.Seal(s, zeroNonce[:], p, []byte(label)))
	}
	pt := randBytes(9, 10)
	good := h.chunk(10)
	forgedChunk := child{h: forge(labelChunk, pt), size: 10}
	forgedNode := child{h: forge(labelNode, encodeNode(nil, 1, []child{good})), size: 10}
	full := h.chunk(MinChunkSize)
	kids := make([]child, Fanout)
	for i := range kids {
		kids[i] = full
	}
	for name, id := range map[string]ID{
		"chunk": h.root(1, forgedChunk),
		"node":  h.root(2, h.node(1, kids...), forgedNode),
		"root":  ID(forge(labelRoot, encodeNode(&h.ks.commit, 1, []child{good}))),
	} {
		if err := h.read(id); !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrWrongKey) {
			t.Fatalf("%s: %v, want ErrCorrupt", name, err)
		}
	}
	if _, err := h.ks.open(nil, labelChunk, h.m.objs[forgedChunk.h]); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("open = %v", err)
	}
}

// Two files under two keys share no object, even with equal bytes, at every size.
func TestNoObjectsSharedAcrossKeys(t *testing.T) {
	for _, n := range []int{0, 1, 1000, MinChunkSize - 1, MinChunkSize, 6 << 20} {
		data := randBytes(10, n)
		a, b := newMem(), newMem()
		mustWrite(t, New(a), NewKey(), data)
		mustWrite(t, New(b), NewKey(), data)
		for h := range b.objs {
			if _, ok := a.objs[h]; ok {
				t.Fatalf("%d bytes: an object is shared across keys", n)
			}
		}
	}
}
