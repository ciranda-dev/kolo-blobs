package koloblobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"
	"testing/iotest"

	kololog "github.com/ciranda-dev/kolo-log"
)

// A node that decodes encodes back to the same bytes: one node, one encoding.
func FuzzDecodeNode(f *testing.F) {
	var commit [32]byte
	c := child{h: Hash{1}, size: 5}
	f.Add(encodeNode(&commit, 1, []child{c}), true)
	f.Add(encodeNode(&commit, 1, nil), true)
	f.Add(encodeNode(nil, 2, []child{c, c}), false)
	f.Add([]byte{1, 0}, false)
	f.Fuzz(func(t *testing.T, b []byte, root bool) {
		commit, height, kids, err := decodeNode(b, root, &v0)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error %v does not wrap ErrCorrupt", err)
			}
			return
		}
		var cp *[32]byte
		if root {
			cp = &commit
		}
		if !bytes.Equal(encodeNode(cp, height, kids), b) {
			t.Fatal("decoded node encodes to other bytes")
		}
		var sum uint64
		for _, c := range kids {
			if c.size == 0 || c.size > MaxSize-sum {
				t.Fatalf("child size %d accepted", c.size)
			}
			sum += c.size
		}
	})
}

// Any root plaintext sealed with the key, over a few real chunks and nodes, opens and reads without a
// panic, returning only the documented errors and bytes that the tree vouches for.
func FuzzOpenRoot(f *testing.F) {
	key := Key{9}
	ks, err := deriveKeys(key)
	if err != nil {
		f.Fatal(err)
	}
	m := newMem()
	sealPut := func(label string, p []byte) Hash {
		o, err := ks.seal(nil, label, p)
		if err != nil {
			f.Fatal(err)
		}
		h := hashOf(o)
		m.Put(context.Background(), h, o)
		return h
	}
	small := child{h: sealPut(labelChunk, []byte("hello")), size: 5}
	node := child{h: sealPut(labelNode, encodeNode(nil, 1, []child{small})), size: 5}
	f.Add(encodeNode(&ks.commit, 1, []child{small}))
	f.Add(encodeNode(&ks.commit, 2, []child{node, node}))
	f.Add(encodeNode(&ks.commit, 1, nil))
	f.Fuzz(func(t *testing.T, pt []byte) {
		o, err := ks.seal(nil, labelRoot, pt)
		if err != nil {
			t.Fatal(err)
		}
		h := hashOf(o)
		mb := &memBackend{objs: map[Hash][]byte{h: o, small.h: m.objs[small.h], node.h: m.objs[node.h]}, gets: map[Hash]int{}}
		s := New(mb)
		r, err := s.Open(context.Background(), ID(h), key)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrWrongKey) {
				t.Fatalf("Open: %v", err)
			}
			return
		}
		defer r.Close()
		b, err := io.ReadAll(io.LimitReader(r, 1<<20))
		if err != nil && !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrNotFound) {
			t.Fatalf("Read: %v", err)
		}
		if len(b)%5 != 0 || !bytes.Equal(b, bytes.Repeat([]byte("hello"), len(b)/5)) {
			t.Fatalf("read %q", b)
		}
	})
}

// Any bytes served as a root object are refused without a panic.
func FuzzOpenObject(f *testing.F) {
	f.Add(make([]byte, ObjectOverhead))
	f.Add(sealed(f, Key{1}, labelRoot, encodeNode(&[32]byte{}, 1, nil)))
	f.Fuzz(func(t *testing.T, obj []byte) {
		h := hashOf(obj)
		s := New(&memBackend{objs: map[Hash][]byte{h: obj}, gets: map[Hash]int{}})
		_, err := s.Open(context.Background(), ID(h), Key{1})
		if err == nil || (!errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrWrongKey)) {
			t.Fatalf("Open = %v", err)
		}
	})
}

// The chunker cuts any input into chunks within the size rules, however the source splits its reads.
func FuzzChunker(f *testing.F) {
	f.Add([]byte("some bytes to cut"), uint8(3), uint8(4), uint16(64))
	f.Add(make([]byte, 5000), uint8(16), uint8(6), uint16(300))
	f.Fuzz(func(t *testing.T, data []byte, minB uint8, avgBits uint8, maxB uint16) {
		p := params{fanout: 2, minChunk: int(minB), avgBits: int(avgBits%8) + 3, maxChunk: int(maxB)}
		if p.maxChunk < 1 || p.minChunk > p.maxChunk {
			return
		}
		ks, err := deriveKeys(Key{byte(minB)})
		if err != nil {
			t.Fatal(err)
		}
		cut := func(r io.Reader) [][]byte {
			c := newChunker(r, &ks.gear, &p)
			var out [][]byte
			for {
				b, err := c.next()
				if err != nil {
					t.Fatal(err)
				}
				if b == nil {
					return out
				}
				out = append(out, bytes.Clone(b))
			}
		}
		chunks := cut(bytes.NewReader(data))
		if !bytes.Equal(bytes.Join(chunks, nil), data) {
			t.Fatal("chunks do not join to the input")
		}
		for i, c := range chunks {
			if len(c) == 0 || len(c) > p.maxChunk || (i < len(chunks)-1 && len(c) < p.minChunk) {
				t.Fatalf("chunk %d of %d has %d bytes", i, len(chunks), len(c))
			}
		}
		for _, r := range []io.Reader{iotest.OneByteReader(bytes.NewReader(data)), iotest.HalfReader(bytes.NewReader(data))} {
			again := cut(r)
			if len(again) != len(chunks) {
				t.Fatal("another read pattern cut other chunks")
			}
			for i := range again {
				if !bytes.Equal(again[i], chunks[i]) {
					t.Fatal("another read pattern cut other chunks")
				}
			}
		}
	})
}

// ReadAt at any offset and length returns the blob's bytes.
func FuzzReadAt(f *testing.F) {
	data := randBytes(61, 300<<10)
	p := fixedParams(16, 1000)
	s := withParams(newMem(), p)
	key := NewKey()
	id := mustWrite(f, s, key, data)
	r, err := s.Open(context.Background(), id, key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(int64(0), uint32(10))
	f.Add(int64(len(data)-1), uint32(10))
	f.Fuzz(func(t *testing.T, off int64, n uint32) {
		buf := make([]byte, n%(1<<16))
		k, err := r.ReadAt(buf, off)
		switch {
		case off < 0:
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("ReadAt(%d) = %v", off, err)
			}
		case off >= int64(len(data)):
			if k != 0 || (len(buf) > 0 && err != io.EOF) {
				t.Fatalf("ReadAt past the end = %d, %v", k, err)
			}
		default:
			want := data[off:min(off+int64(len(buf)), int64(len(data)))]
			if !bytes.Equal(buf[:k], want) || (k < len(buf)) != (err == io.EOF) {
				t.Fatalf("ReadAt(%d, %d) = %d, %v", len(buf), off, k, err)
			}
		}
	})
}

// A Write through the pipeline stores the objects, in the order, under the ID of a Write in turn, for any input and
// number of workers, and a panic of Put at any object reaches the caller.
func FuzzWritePipeline(f *testing.F) {
	f.Add([]byte("some bytes"), uint8(3), uint8(0))
	f.Add(randBytes(70, 90<<10), uint8(7), uint8(5))
	f.Fuzz(func(t *testing.T, data []byte, workers uint8, panicAt uint8) {
		serial := newRecorder()
		want, err := smallStore(serial, 1).Write(context.Background(), Key{4}, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		par := newRecorder()
		got, err := smallStore(par, int(workers%8)+1).Write(context.Background(), Key{4}, bytes.NewReader(data))
		if err != nil || got != want || !slices.Equal(par.order, serial.order) {
			t.Fatalf("pipeline: %v, ID %s want %s, %d objects want %d", err, got, want, len(par.order), len(serial.order))
		}
		if n := int(panicAt); n > 0 && n <= len(serial.order) {
			k := &keeper{recorder: *newRecorder(), panicAt: n}
			if v := caught(func() { smallStore(k, int(workers%8)+1).Write(context.Background(), Key{4}, bytes.NewReader(data)) }); v != errPut {
				t.Fatalf("panic at Put %d of %d: recovered %v", n, len(serial.order), v)
			}
		}
	})
}

// The windows of a scan index the entries of any log, whatever the mix of deleted, keyless and repeated entries and
// the entry that fails to read, as a scan in turn does, and a recheck after the keys arrive finds the rest.
func FuzzLogBackendScan(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 0, 0, 1, 1}, uint8(200))
	f.Add(bytes.Repeat([]byte{2}, 150), uint8(70))
	f.Fuzz(func(t *testing.T, kinds []byte, failAt uint8) {
		boom := errors.New("read failed")
		fl := &fakeLog{}
		for i, k := range kinds {
			v, err := []byte{byte(i % 5), 7}, error(nil) // repeated objects: i and i+5 hold one
			switch k % 4 {
			case 1:
				err = kololog.ErrDeleted
			case 2:
				err = kololog.ErrKeyUnavailable
			}
			fl.vals, fl.errs = append(fl.vals, v), append(fl.errs, err)
		}
		if i := int(failAt); i < len(kinds) {
			fl.errs[i] = boom
		}
		par, ser := NewLogBackend(fl), NewLogBackend(fl)
		perr := par.catchUp(context.Background())
		var serr error
		for i := range uint64(len(kinds)) {
			var keyless bool
			if keyless, serr = ser.read(context.Background(), i); serr != nil {
				break
			}
			if keyless {
				ser.keyless = append(ser.keyless, i)
			}
			ser.next++
		}
		if errors.Is(perr, boom) != errors.Is(serr, boom) || (perr == nil) != (serr == nil) || par.next != ser.next || fmt.Sprint(par.keyless) != fmt.Sprint(ser.keyless) || fmt.Sprint(par.index) != fmt.Sprint(ser.index) {
			t.Fatalf("windows: next %d err %v keyless %v, in turn: next %d err %v keyless %v", par.next, perr, par.keyless, ser.next, serr, ser.keyless)
		}
		for i, e := range fl.errs { // the keys arrive
			if errors.Is(e, kololog.ErrKeyUnavailable) {
				fl.errs[i] = nil
			}
		}
		if perr == nil {
			if err := par.recheck(context.Background()); err != nil || len(par.keyless) != 0 {
				t.Fatalf("recheck: %v, %d keyless left", err, len(par.keyless))
			}
		}
	})
}
