# kolo-blobs

Encrypted, content-addressed file storage for Kolo.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

kolo-blobs cuts a file into content-defined chunks with [FastCDC](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia), encrypts each with [AES-GCM (NIST SP 800-38D)](https://doi.org/10.6028/NIST.SP.800-38D) under keys derived by [HKDF (RFC 5869)](https://www.rfc-editor.org/info/rfc5869), and names it by its [SHA-256 (FIPS 180-4)](https://doi.org/10.6028/NIST.FIPS.180-4) hash. It is the content layer under kolo-files: a file's bytes and nothing else, with no names, folders or versions. `Write` cuts a file into content-defined chunks, encrypts each under keys derived from a random per-file key, builds a Merkle tree over them and returns the blob's ID, the hash of the tree's root. `Open` returns a reader that checks every chunk against the tree while it streams, and reads any range by fetching only the chunks that cover it.

With `NewLogBackend`, blobs are entries of a [kolo-store](https://github.com/ciranda-dev/kolo-store) log, so they travel with [kolo-sync](https://github.com/ciranda-dev/kolo-sync) and rest on [kolo-pin](https://github.com/ciranda-dev/kolo-pin) pinning peers, which hold only ciphertext and never a key.

It is pure Go: no cgo and nothing to install.

## Install

```sh
go get github.com/ciranda-dev/kolo-blobs
```

## Quick start

This program stores a file in a kolo-store log on disk, in the directory given as argument, such as `go run . "$(mktemp -d)/store"`. It needs a module that requires kolo-blobs, kolo-id and kolo-store.

```go
// Command basic stores a file as a blob in a kolo-store log on disk, in the directory given as argument,
// reads a range of it back, then stores an edited version with the same key, which adds only a few entries.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"os"

	koloblobs "github.com/ciranda-dev/kolo-blobs"
	koloid "github.com/ciranda-dev/kolo-id"
	kolostore "github.com/ciranda-dev/kolo-store"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: basic DIR")
	}
	ctx := context.Background()
	db, err := kolostore.OpenPebble(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	st := kolostore.New(db)
	defer st.Close()
	me, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	l, err := st.Create(me)
	if err != nil {
		log.Fatal(err)
	}
	blobs := koloblobs.New(koloblobs.NewLogBackend(l))

	// A 20 MB file, stored under a new key. The key and the ID are what a reader needs.
	file := make([]byte, 20_000_000)
	rng := rand.NewChaCha8([32]byte{1})
	rng.Read(file)
	key := koloblobs.NewKey()
	id, err := blobs.Write(ctx, key, bytes.NewReader(file))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("stored %d bytes as %d log entries\n", len(file), l.Len())

	r, err := blobs.Open(ctx, id, key)
	if err != nil {
		log.Fatal(err)
	}
	part, err := io.ReadAll(io.NewSectionReader(r, 12_000_000, 16))
	r.Close()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("bytes 12000000 to 12000016 match: %v\n", bytes.Equal(part, file[12_000_000:12_000_016]))

	// An edited version under the same key shares every chunk away from the edit.
	before := l.Len()
	edited := append(append(append([]byte{}, file[:10_000_000]...), "an insertion"...), file[10_000_000:]...)
	if _, err := blobs.Write(ctx, key, bytes.NewReader(edited)); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("the edited version added %d entries\n", l.Len()-before)
}
```

It prints how many log entries the file took: the chunks and one root, 17 to 19 in six runs, since the cut points depend on the random key. Then it prints that the range matches, and `the edited version added 2 entries`: the chunk around the insertion and a new root.

To keep a blob on a pinning peer, add its log with `pin.Add`. A device then reads it from the pinning peer, either by pulling the whole log or by reading ranges through a `RemoteBackend`, with the blob's key and ID, the owner's public key and the content log's ID from whoever shares the file. The code is in the [guide](docs/guide.md#reading-from-a-pinning-peer).

## API

| Symbol | What it does |
|---|---|
| `NewKey()` | A random 32-byte file key. Use one key for one file and its versions. It prints as `[redacted]` |
| `New(backend)` | A `Store` on a `Backend`, safe for concurrent use |
| `Store.Write(ctx, key, src)` | Store `src` as a blob and return its `ID`. The same bytes under the same key give the same ID, so a killed write resumes by running again |
| `Store.Open(ctx, id, key)` | A `Reader` (`io.Reader`, `io.ReaderAt`, `io.Seeker`) that checks every object and reads ranges cheaply |
| `Store.Objects(ctx, id, key)` | Every object of a blob, for object tables and deletion |
| `Store.Stats()` | Totals of bytes and objects written, read and rejected |
| `Backend` | `Get` and `Put` of an object by its SHA-256 |
| `NewLogBackend(log)` | Objects as entries of a kolo-store or kolo-log log, with `Index` |
| `NewRemoteBackend(fetch, locate)` | Read a content log on another peer, one entry per object |

Errors are sentinels that work with `errors.Is`: `ErrNotFound`, `ErrCorrupt`, `ErrWrongKey`, `ErrTooLarge`, `ErrReadOnly`, `ErrClosed` and `ErrInvalidArgument`. None carries key bytes or content.

## How it works

- Chunks are content-defined (FastCDC) with a gear table derived from the file key, about 1 MiB on average. A new version of a file written under the file's key stores only the chunks that changed.
- Each object is encrypted with AES-256-GCM under a key derived from its own content, so equal chunks under one key are one object. Different keys never share an object, and without the key nobody can compute an object or its hash.
- The tree is 256-ary and built while chunks arrive. The blob's ID is the SHA-256 of the root and commits to the key, the size, the shape and every chunk.
- Memory does not depend on the file size: a 10 GiB file is written and read back with a peak heap of 64 MiB or less (82 MiB when the log is on Pebble, whose memtable is most of it).

A storage holder sees object sizes, which chunks two versions share and, for a pinning peer, entry counts and padded sizes. It never sees a key or content. What each party can see is in the [guide](docs/guide.md#what-is-visible-to-storage).

## More

[Guide](docs/guide.md), [formats and design](docs/formats.md), [limits and benchmarks](docs/limits.md), [security policy](SECURITY.md).

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.

## Status

Experimental. The API may change before v1.0.0.
