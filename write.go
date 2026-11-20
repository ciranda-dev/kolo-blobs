package koloblobs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
)

// maxWriteWorkers bounds the goroutines that seal chunks: the chunker, one goroutine, feeds about two gigabytes a
// second, so two sealers keep up with it and more only hold more memory.
//
// keepBuffer is the largest buffer a job keeps for its next chunk; a larger one is dropped, so the buffers do not
// all grow to the size of the largest chunk and the memory stays near the average chunk, not the maximum.
const (
	maxWriteWorkers = 2
	keepBuffer      = 2 << 20
)

// sealJob is one chunk on its way from the chunker to the backend: its plaintext, then its object and hash.
type sealJob struct {
	chunk []byte
	obj   []byte
	h     Hash
	err   error
	done  chan struct{} // closed when obj and h are set
}

func (j *sealJob) clear() {
	clear(j.chunk[:cap(j.chunk)])
	clear(j.obj[:cap(j.obj)])
}

// errPanicked marks a job that failed by a panic; the panic itself is raised again on the caller's goroutine.
var errPanicked = errors.New("koloblobs: panic in the write pipeline")

// panicked keeps the first panic of a goroutine of the pipeline.
type panicked struct {
	mu  sync.Mutex
	set bool
	v   any
}

func (p *panicked) keep(v any) {
	p.mu.Lock()
	if !p.set {
		p.set, p.v = true, v
	}
	p.mu.Unlock()
}

func (s *Store) writeWorkers() int {
	if s.workers > 0 {
		return s.workers
	}
	return max(1, min(runtime.GOMAXPROCS(0), maxWriteWorkers))
}

// Write reads src to its end, stores it as a blob under key and returns its ID; the same bytes and key give
// the same ID, so a Write killed part way is resumed by running it again. It checks ctx between chunks.
//
// Chunking, sealing and Put run as a pipeline, so a Write uses several cores and a slow Put does not hold up the
// chunker. Put is still called from one goroutine, one object at a time in chunk order, so the objects, the tree and
// the ID are those of a Write that does everything in turn. A panic of src or of Put reaches the caller of Write.
func (s *Store) Write(ctx context.Context, key Key, src io.Reader) (ID, error) {
	if s == nil || s.b == nil || src == nil || ctx == nil {
		return ID{}, ErrInvalidArgument
	}
	ks, err := deriveKeys(key)
	if err != nil {
		return ID{}, err
	}
	defer ks.zero()
	c := newChunker(src, &ks.gear, &s.p)
	defer c.release()
	b := &builder{s: s, ks: ks, ctx: ctx}
	var total uint64
	// next reads one chunk; it returns nil at the end of src.
	next := func() ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunk, err := c.next()
		if err != nil || chunk == nil {
			return nil, err
		}
		if uint64(len(chunk)) > s.p.maxSize-total {
			return nil, fmt.Errorf("%w: source longer than %d bytes", ErrTooLarge, s.p.maxSize)
		}
		total += uint64(len(chunk))
		s.bytesWritten.Add(uint64(len(chunk)))
		return chunk, nil
	}
	first, err := next()
	if err != nil {
		return ID{}, err
	}
	if first != nil && !c.last() && s.writeWorkers() > 1 {
		if err := s.writePipeline(ctx, ks, b, first, next); err != nil {
			return ID{}, err
		}
	} else {
		// A file of one chunk, or one worker: everything in turn, with no goroutine.
		var obj []byte
		defer func() { clear(obj) }()
		for chunk := first; chunk != nil; {
			if obj, err = ks.seal(obj[:0], labelChunk, chunk); err != nil {
				return ID{}, err
			}
			h, err := s.putObject(ctx, obj)
			if err != nil {
				return ID{}, err
			}
			if err := b.add(0, child{h: h, size: uint64(len(chunk))}); err != nil {
				return ID{}, err
			}
			if chunk, err = next(); err != nil {
				return ID{}, err
			}
		}
	}
	root, err := b.finish()
	return ID(root), err
}

// writePipeline stores first and every chunk next returns after it. The caller's goroutine reads the chunks, one
// goroutine per worker seals them and one commits the objects in order. Only jobs that come back from the committer
// are reused, so at most workers + 3 chunks are in flight and the memory is bounded whatever the source's size.
// On a panic the goroutines end, the buffers are cleared and the panic is raised again on the caller's goroutine.
func (s *Store) writePipeline(ctx context.Context, ks *keys, b *builder, first []byte, next func() ([]byte, error)) error {
	workers := s.writeWorkers()
	n := workers + 3
	pctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	all := make([]*sealJob, n)
	free := make(chan *sealJob, n)
	for i := range all {
		all[i] = &sealJob{}
		free <- all[i]
	}
	work := make(chan *sealJob, n) // the jobs come from free, so these sends never block
	order := make(chan *sealJob, n)
	var wg sync.WaitGroup
	var pan panicked
	// guard runs f and turns its panic into errPanicked.
	guard := func(f func() error) (err error) {
		defer func() {
			if r := recover(); r != nil {
				pan.keep(r)
				err = errPanicked
			}
		}()
		return f()
	}
	for range workers {
		wg.Go(func() {
			for j := range work {
				j.err = guard(func() error {
					var err error
					if j.obj, err = ks.seal(j.obj[:0], labelChunk, j.chunk); err == nil {
						j.h = Hash(sha256.Sum256(j.obj))
					}
					return err
				})
				close(j.done)
			}
		})
	}
	committed := make(chan error, 1)
	go func() {
		var failed error
		for j := range order {
			<-j.done
			if failed == nil {
				err := context.Cause(pctx)
				if err == nil {
					err = j.err
				}
				if err == nil {
					err = guard(func() error {
						if err := s.putHash(pctx, j.h, j.obj); err != nil {
							return err
						}
						return b.add(0, child{h: j.h, size: uint64(len(j.chunk))})
					})
				}
				if failed = err; err != nil {
					cancel(err)
				}
			}
			if cap(j.chunk) > keepBuffer {
				clear(j.chunk[:cap(j.chunk)])
				j.chunk = nil
			}
			if cap(j.obj) > keepBuffer {
				clear(j.obj[:cap(j.obj)])
				j.obj = nil
			}
			free <- j // after a failure too, so the reader never waits for a job nobody gives back
		}
		committed <- failed
	}()
	finished := false
	defer func() {
		if !finished { // the source panicked: the panic goes on, after the goroutines end
			close(work)
			close(order)
			wg.Wait()
			<-committed
		}
		for _, j := range all {
			j.clear()
		}
		if finished && pan.set {
			panic(pan.v)
		}
	}()
	var readErr, stopped error
	for chunk := first; chunk != nil; {
		var j *sealJob
		// Checked first: after a failure both cases below are ready and select would pick one at random.
		if pctx.Err() == nil {
			select {
			case j = <-free:
			case <-pctx.Done():
			}
		}
		if j == nil {
			stopped = context.Cause(pctx)
			break
		}
		j.chunk = append(j.chunk[:0], chunk...)
		j.done = make(chan struct{})
		work <- j
		order <- j
		if chunk, readErr = next(); readErr != nil {
			break
		}
	}
	finished = true
	close(work)
	close(order)
	wg.Wait()
	failed := <-committed
	switch {
	case failed != nil:
		return failed
	case readErr != nil:
		return readErr
	}
	return stopped
}
