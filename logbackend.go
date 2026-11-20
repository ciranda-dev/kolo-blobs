package koloblobs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	kololog "github.com/ciranda-dev/kolo-log"
)

// Log is what a LogBackend reads: a kolo-store or kolo-log log or replica. One with an
// Append(v any) (uint64, error) method, such as a log, can also be written to. Get and EntryInfo must be
// safe for concurrent use: a LogBackend reads several entries at once when it indexes a log.
type Log interface {
	Len() uint64
	Get(index uint64) ([]byte, error)
	EntryInfo(index uint64) (kololog.EntryInfo, error)
}

type appender interface {
	Append(v any) (uint64, error)
}

// LogBackend keeps objects as entries of a log, one per entry, indexed by hash on first use; it is safe for
// concurrent use.
type LogBackend struct {
	log Log

	mu      sync.Mutex
	index   map[Hash][]uint64 // every indexed entry holding the object
	next    uint64            // entries below next are indexed, deleted or in keyless
	keyless []uint64          // entries whose kolo-log key is not here yet
}

// NewLogBackend returns a Backend on l. Put appends to l if l has an Append method, and returns
// ErrReadOnly otherwise.
func NewLogBackend(l Log) *LogBackend {
	return &LogBackend{log: l, index: make(map[Hash][]uint64)}
}

// Get returns the object stored under h, or ErrNotFound. Entries that are deleted or whose kolo-log
// key is not here cannot be read, and their objects are not found. ctx bounds the index scan.
func (b *LogBackend) Get(ctx context.Context, h Hash) ([]byte, error) {
	if b == nil || b.log == nil || ctx == nil {
		return nil, ErrInvalidArgument
	}
	i, err := b.lookup(ctx, h)
	if err != nil {
		return nil, err
	}
	// The log is read outside the lock, so concurrent readers do not wait for each other's decryption.
	v, err := b.log.Get(i)
	if errors.Is(err, kololog.ErrDeleted) {
		return nil, fmt.Errorf("%w: entry %d was deleted", ErrNotFound, i)
	}
	if err != nil {
		return nil, backendFailure("read entry %d: %w", i, err)
	}
	return v, nil
}

// Index returns the entry index of the object h in the log, or an error wrapping ErrNotFound; a deleted
// entry is not found. ctx bounds the index scan.
func (b *LogBackend) Index(ctx context.Context, h Hash) (uint64, error) {
	if b == nil || b.log == nil || ctx == nil {
		return 0, ErrInvalidArgument
	}
	return b.lookup(ctx, h)
}

// lookup returns the entry index of h, indexing new entries first if h is not known yet.
func (b *LogBackend) lookup(ctx context.Context, h Hash) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	i, ok, err := b.live(h)
	if err != nil || ok {
		return i, err
	}
	if err := b.catchUp(ctx); err != nil {
		return 0, err
	}
	if i, ok, err = b.live(h); err != nil || ok {
		return i, err
	}
	if err := b.recheck(ctx); err != nil {
		return 0, err
	}
	if i, ok, err = b.live(h); err != nil || ok {
		return i, err
	}
	if len(b.keyless) > 0 {
		return 0, fmt.Errorf("%w (%d entries of the log have no key here)", ErrNotFound, len(b.keyless))
	}
	return 0, ErrNotFound
}

// live returns an indexed entry of h that the log has not deleted since, dropping the deleted ones.
func (b *LogBackend) live(h Hash) (uint64, bool, error) {
	idx := b.index[h]
	for len(idx) > 0 {
		i := idx[0]
		info, err := b.log.EntryInfo(i)
		if err != nil {
			return 0, false, backendFailure("read entry %d: %w", i, err)
		}
		if !info.Deleted {
			b.index[h] = idx
			return i, true, nil
		}
		idx = idx[1:]
	}
	delete(b.index, h)
	return 0, false, nil
}

// Put appends obj as a new entry unless the log already holds it live. It returns ErrInvalidArgument if h
// is not the SHA-256 of obj and ErrTooLarge over MaxObjectSize. ctx bounds the index scan.
func (b *LogBackend) Put(ctx context.Context, h Hash, obj []byte) error {
	if b == nil || b.log == nil || ctx == nil {
		return ErrInvalidArgument
	}
	if len(obj) > MaxObjectSize {
		return fmt.Errorf("%w: object of %d bytes", ErrTooLarge, len(obj))
	}
	if sha256.Sum256(obj) != h {
		return fmt.Errorf("%w: hash does not match the object", ErrInvalidArgument)
	}
	a, ok := b.log.(appender)
	if !ok {
		return ErrReadOnly
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.catchUp(ctx); err != nil {
		return err
	}
	if _, ok, err := b.live(h); err != nil || ok {
		return err
	}
	i, err := a.Append(obj)
	if err != nil {
		return backendFailure("append entry: %w", err)
	}
	b.index[h] = []uint64{i} // live found no live entry and dropped the dead ones
	if i == b.next {
		b.next++
	}
	return nil
}

// catchUpWindow is how many new entries catchUp reads at once, on up to maxCatchUpReaders goroutines: reading an entry
// decrypts it and hashing takes as long again, so one goroutine would be slow on the log of a large blob.
const (
	catchUpWindow     = 64
	maxCatchUpReaders = 4
)

// catchUp indexes the entries added since the last call; it stops with ctx.Err() when ctx ends, keeping what it
// indexed. The entries are read in windows on several goroutines and indexed in the order of the log, so the index and
// an error are those of a read in turn.
func (b *LogBackend) catchUp(ctx context.Context) error {
	for n := b.log.Len(); b.next < n; {
		w := int(min(n-b.next, catchUpWindow))
		res := b.probeWindow(ctx, func(k int) uint64 { return b.next + uint64(k) }, w)
		for k := range res {
			if p := b.settle(ctx, res[k], b.next); p.err != nil {
				return p.err
			} else if b.apply(p, b.next) {
				b.keyless = append(b.keyless, b.next)
			}
			b.next++
		}
	}
	return nil
}

// recheck reads again the entries that had no key and indexes those that have it now, in windows like catchUp. The
// log does not report new keys, so only a lookup that missed calls it: Put does not, and appends again an object
// whose key arrived since.
func (b *LogBackend) recheck(ctx context.Context) error {
	still := b.keyless[:0]
	for off := 0; off < len(b.keyless); off += catchUpWindow {
		w := min(len(b.keyless)-off, catchUpWindow)
		res := b.probeWindow(ctx, func(k int) uint64 { return b.keyless[off+k] }, w)
		for k := range res {
			i := b.keyless[off+k]
			p := b.settle(ctx, res[k], i)
			if p.err != nil {
				b.keyless = append(still, b.keyless[off+k:]...)
				return p.err
			}
			if b.apply(p, i) {
				still = append(still, i)
			}
		}
	}
	b.keyless = still
	return nil
}

// probeWindow probes the w entries at(0) to at(w-1), on up to maxCatchUpReaders goroutines. A reader stops at the first
// error or when ctx ends, leaving the entries it did not reach unread.
func (b *LogBackend) probeWindow(ctx context.Context, at func(k int) uint64, w int) []probed {
	res := make([]probed, w)
	for k := range res {
		res[k].unread = true
	}
	readers := max(1, min(runtime.GOMAXPROCS(0), maxCatchUpReaders))
	if readers == 1 || w < 4 {
		for k := range res {
			if res[k] = b.probe(ctx, at(k)); res[k].err != nil {
				break
			}
		}
		return res
	}
	var next atomic.Int64
	var failed atomic.Bool
	var wg sync.WaitGroup
	for range min(readers, w) {
		wg.Go(func() {
			for {
				k := int(next.Add(1)) - 1
				if k >= w || failed.Load() || ctx.Err() != nil {
					return
				}
				if res[k] = b.probe(ctx, at(k)); res[k].err != nil {
					failed.Store(true)
				}
			}
		})
	}
	wg.Wait()
	return res
}

// settle returns the outcome of entry i for a result of probeWindow: an entry a reader did not reach is read now, in turn,
// unless ctx ended, so the first error is the one of a read in turn.
func (b *LogBackend) settle(ctx context.Context, p probed, i uint64) probed {
	if p.err == nil && p.unread {
		if p.err = ctx.Err(); p.err == nil {
			p = b.probe(ctx, i)
		}
	}
	return p
}

// probed is what reading one entry found: the entry has no key here, is deleted or has the object that hashes to h.
type probed struct {
	keyless bool
	skip    bool // deleted: nothing to index
	unread  bool // not read: a reader stopped first
	h       Hash
	err     error
}

// probe reads entry i, which it does not index; it is safe to call from several goroutines.
func (b *LogBackend) probe(ctx context.Context, i uint64) probed {
	if err := ctx.Err(); err != nil {
		return probed{err: err}
	}
	info, err := b.log.EntryInfo(i)
	switch {
	case err != nil:
		return probed{err: backendFailure("read entry %d: %w", i, err)}
	case info.Deleted:
		return probed{skip: true}
	case !info.Keyed:
		return probed{keyless: true}
	}
	v, err := b.log.Get(i)
	switch {
	case errors.Is(err, kololog.ErrKeyUnavailable):
		return probed{keyless: true}
	case errors.Is(err, kololog.ErrDeleted):
		return probed{skip: true}
	case err != nil:
		return probed{err: backendFailure("read entry %d: %w", i, err)}
	}
	return probed{h: Hash(sha256.Sum256(v))}
}

// apply indexes what probe found for entry i and reports whether the entry lacks its key.
func (b *LogBackend) apply(p probed, i uint64) (keyless bool) {
	if !p.keyless && !p.skip {
		b.index[p.h] = append(b.index[p.h], i)
	}
	return p.keyless
}
