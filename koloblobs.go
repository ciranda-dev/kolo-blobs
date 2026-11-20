package koloblobs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync/atomic"
)

const (
	// KeySize is the size in bytes of a file key.
	KeySize = 32
	// HashSize is the size in bytes of an object hash and a content ID.
	HashSize = sha256.Size
	// MaxObjectSize is the largest object, the largest kolo-log entry value that kolo-sync carries.
	MaxObjectSize = 4128764
	// ObjectOverhead is what encryption adds to a chunk or node: a 32-byte content MAC and a 16-byte tag.
	ObjectOverhead = 48
	// MaxChunkSize is the largest chunk of plaintext, so that its object is at most MaxObjectSize.
	MaxChunkSize = MaxObjectSize - ObjectOverhead
	// MinChunkSize is the smallest chunk the chunker cuts; only a blob's last chunk can be smaller.
	MinChunkSize = 256 << 10
	// Fanout is the most children a tree node lists.
	Fanout = 256
	// MaxHeight is the most node levels above the chunks; 256^6 chunks of MinChunkSize exceed MaxSize.
	MaxHeight = 6
	// MaxSize is the largest blob in bytes, the largest offset of io.Seeker.
	MaxSize = math.MaxInt64
)

var (
	// ErrInvalidArgument means a nil store, backend, log, source, context or function, a negative or
	// out-of-range offset, an unknown whence, or a Put whose hash is not the object's.
	ErrInvalidArgument = errors.New("koloblobs: invalid argument")
	// ErrNotFound means the backend does not have an object of the blob.
	ErrNotFound = errors.New("koloblobs: object not found")
	// ErrCorrupt means an object does not match its hash, does not decrypt or breaks a tree rule.
	ErrCorrupt = errors.New("koloblobs: object does not verify")
	// ErrWrongKey means the blob's root does not open under the key, or commits to another key.
	ErrWrongKey = errors.New("koloblobs: wrong key for this blob")
	// ErrTooLarge means a source longer than MaxSize, or an object over MaxObjectSize.
	ErrTooLarge = errors.New("koloblobs: too large")
	// ErrReadOnly means Put on a RemoteBackend, or on a LogBackend whose log cannot append.
	ErrReadOnly = errors.New("koloblobs: backend is read-only")
	// ErrClosed means a Read, ReadAt or Seek on a closed Reader.
	ErrClosed = errors.New("koloblobs: reader closed")
)

var sentinels = []error{ErrInvalidArgument, ErrNotFound, ErrCorrupt, ErrWrongKey, ErrTooLarge, ErrReadOnly, ErrClosed}

// Key is a file key, for one file and its versions only; it formats and logs as [redacted].
type Key [KeySize]byte

// NewKey returns a random file key; use a new one for each file.
func NewKey() Key {
	var k Key
	rand.Read(k[:])
	return k
}

// String returns [redacted].
func (Key) String() string { return "[redacted]" }

// Format writes [redacted] for every verb, so no fmt verb prints the key.
func (Key) Format(f fmt.State, _ rune) { f.Write([]byte("[redacted]")) }

// LogValue returns [redacted].
func (Key) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// MarshalJSON returns "[redacted]"; store a key only in a binary encoding.
func (Key) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// Hash is the SHA-256 of an object, the name a Backend stores it under.
type Hash [HashSize]byte

// String returns the hash as lowercase hex.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// ID is a blob's content ID: the hash of its root object.
type ID [HashSize]byte

// String returns the ID as lowercase hex.
func (id ID) String() string { return hex.EncodeToString(id[:]) }

// Backend holds objects by hash. Implementations must be safe for concurrent use.
type Backend interface {
	// Get returns the object stored under h, or an error wrapping ErrNotFound. The caller does not modify it.
	// A Get that waits on the network returns when ctx is done.
	Get(ctx context.Context, h Hash) ([]byte, error)
	// Put stores obj under h, its SHA-256, atomically; an object already stored is not stored again. Put must not keep obj.
	Put(ctx context.Context, h Hash, obj []byte) error
}

// Stats are a Store's totals since New.
type Stats struct {
	BytesWritten   uint64 // plaintext bytes Write read from its sources
	BytesRead      uint64 // plaintext bytes returned by Readers
	ObjectsPut     uint64 // objects passed to Backend.Put
	ObjectsFetched uint64 // objects returned by Backend.Get
	Rejected       uint64 // fetched objects that failed a check
}

// Store writes and reads blobs on a Backend; it is safe for concurrent use.
type Store struct {
	b       Backend
	p       params
	workers int // goroutines that seal chunks in Write; 0 is the default

	bytesWritten, bytesRead, put, fetched, rejected atomic.Uint64
}

// params are the format parameters; tests shrink them to reach deep trees with little data.
type params struct {
	fanout   int
	minChunk int
	avgBits  int // log2 of the average chunk size
	maxChunk int
	maxSize  uint64
}

var v0 = params{fanout: Fanout, minChunk: MinChunkSize, avgBits: 20, maxChunk: MaxChunkSize, maxSize: MaxSize}

// New returns a Store on b.
func New(b Backend) *Store { return &Store{b: b, p: v0} }

// Stats returns the store's totals; it is safe to call at any time.
func (s *Store) Stats() Stats {
	return Stats{
		BytesWritten:   s.bytesWritten.Load(),
		BytesRead:      s.bytesRead.Load(),
		ObjectsPut:     s.put.Load(),
		ObjectsFetched: s.fetched.Load(),
		Rejected:       s.rejected.Load(),
	}
}

func (s *Store) putObject(ctx context.Context, obj []byte) (Hash, error) {
	h := Hash(sha256.Sum256(obj))
	return h, s.putHash(ctx, h, obj)
}

// putHash stores obj, whose SHA-256 is h.
func (s *Store) putHash(ctx context.Context, h Hash, obj []byte) error {
	if err := s.b.Put(ctx, h, obj); err != nil {
		return backendErr("put object", err)
	}
	s.put.Add(1)
	return nil
}

// failure marks an error that this package's own backends already named.
type failure struct{ error }

func (f failure) Unwrap() error { return f.error }

// backendFailure is fmt.Errorf for an error that backendErr passes on as it is.
func backendFailure(format string, a ...any) error {
	return failure{fmt.Errorf("koloblobs: "+format, a...)}
}

// backendErr names what failed for an error from a Backend, unless it is one of this package's sentinels or already named.
func backendErr(what string, err error) error {
	var f failure
	if errors.As(err, &f) {
		return err
	}
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return err
		}
	}
	return fmt.Errorf("koloblobs: %s: %w", what, err)
}

// fetch gets an object and checks its size and hash.
func (s *Store) fetch(ctx context.Context, h Hash) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	obj, err := s.b.Get(ctx, h)
	if err != nil {
		return nil, backendErr("get object", err)
	}
	s.fetched.Add(1)
	if len(obj) < ObjectOverhead || len(obj) > MaxObjectSize {
		s.rejected.Add(1)
		return nil, fmt.Errorf("%w: object of %d bytes", ErrCorrupt, len(obj))
	}
	if sha256.Sum256(obj) != h {
		s.rejected.Add(1)
		return nil, fmt.Errorf("%w: object does not match its hash", ErrCorrupt)
	}
	return obj, nil
}
