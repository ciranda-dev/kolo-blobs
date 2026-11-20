# Guide

Walkthrough of the API, reading from a pinning peer, the errors and what a storage holder can see. Numbers and bounds are in [limits.md](limits.md), the formats and the encryption design in [formats.md](formats.md). A complete program is in the README.

## API

- `NewKey() Key` returns a random 32-byte file key. Use one key for
  exactly one file and its versions, and a new key for every other file
  (kolo-files generates one per file). Reusing a key across files makes
  their equal chunks equal ciphertext, which any storage holder sees. A
  `Key` value, a pointer to one, or one in an exported struct field prints
  and logs as `[redacted]` with fmt, slog and encoding/json. In an
  unexported struct field, fmt's `%v` and `%+v` and slog's text handler
  print the raw bytes, so never keep a key in an unexported field of a
  struct that is printed or logged. Use `key[:]` for the bytes and keep
  them only in a binary, encrypted form.
- `New(backend) *Store` returns a store on a `Backend`. A `Store` is safe
  for concurrent use.
- `Store.Write(ctx, key, src) (ID, error)` reads `src` to its end and
  stores it as a blob under `key`. The same bytes under the same key give
  the same ID and store no new object, so a write that was killed is
  resumed by running it again with the same key and source, and a new
  version of a file written with the file's key stores only the chunks
  that changed. `ctx` is checked between chunks. A panic of `src` or of the
  backend's `Put` reaches the caller of `Write`, which may recover it, with
  the goroutines of the write ended and its buffers cleared.
- `Store.Open(ctx, id, key) (*Reader, error)` fetches and checks the
  root. The Reader passes `ctx` to every `Backend.Get` it makes, since
  io's read methods take no context, so ending `ctx` ends its reads with
  `ctx.Err()`.
  `Reader` is an `io.Reader`, `io.ReaderAt` and `io.Seeker`, safe for
  concurrent use; concurrent `ReadAt` calls run one at a time (the lock is
  held while a chunk is fetched), so use one Reader per goroutine to fetch
  in parallel. `Size()` is the blob's size. `ReadAt(p, off)` reads a
  range, fetching one node per tree level and only the chunks that cover
  it; `io.NewSectionReader(r, start, length)` gives a range as a stream.
  Every object is checked before any of its bytes are returned; a read
  that hits a bad or missing object returns the bytes before it and the
  error. `Close()` clears the reader's subkeys and chunk buffer; the
  AES ciphers' internal copies of object keys stay in memory until the
  runtime reuses them, as with kolo-log.
- `Store.Objects(ctx, id, key) iter.Seq2[Hash, error]` lists every
  object of a blob: the root first, then each node followed by the objects
  under it. It fetches and checks the root and nodes, not the chunks, and
  holds one node per level. An object the blob holds more than once is
  listed each time. It stops at the first error, yielded with a zero
  `Hash`. kolo-files uses it with `LogBackend.Index` to list a version's
  entries for an object table or for deletion. Its work follows the size
  the root claims, not the objects stored: a key holder can make a blob of
  a few objects whose listing yields about one hash per `MinChunkSize` of
  claimed size (up to about 2^45 for `MaxSize`), with one node fetch per
  256. Give it a context with a deadline for blobs you do not trust.
- `Store.Stats() Stats` returns totals since `New`, read with atomics:
  `BytesWritten` (plaintext read by `Write`), `BytesRead` (plaintext
  returned by readers), `ObjectsPut`, `ObjectsFetched` and `Rejected`
  (fetched objects that failed a check). There is nothing per blob.
- `Backend` is `Get(ctx, h Hash) ([]byte, error)` and
  `Put(ctx, h Hash, obj []byte) error`, safe for concurrent use. `Get`
  returns an error wrapping `ErrNotFound` for a missing object, and one
  that waits on the network returns when `ctx` ends. `Put` stores
  `obj` under its SHA-256 `h` atomically, does nothing for an object it
  has, and does not keep `obj`.
- `NewLogBackend(log) *LogBackend` keeps each object as one entry of a
  kolo-store or kolo-log log or replica (anything with `Len`, `Get` and
  `EntryInfo`, and `Append` to be written to). It indexes the log's
  entries by object hash. The first `Get`, `Put` or `Index` on a new
  `LogBackend` reads and decrypts every live entry of the log that has its
  key, once, under the backend's lock (deleted and keyless entries are
  skipped from `EntryInfo` without reading them); its cost grows with the
  whole log, not the blob, and the context ends it with `ctx.Err()`.
  Later calls read only entries added since. For range reads on a large
  log without that scan, use `NewRemoteBackend` with a `fetch` that reads
  the local log (`log.Get`) and a `locate` from an object table, as
  kolo-files does. The index keeps every entry that holds an object (about
  140 bytes per entry, growing with the log), checks a hit with `EntryInfo`
  and moves on to another entry when one was deleted. `Put` appends an
  object only when no indexed entry holding it is live, so writing a
  deleted blob again stores it again; on a replica it returns
  `ErrReadOnly`. It refuses an object whose hash
  is not `h` (`ErrInvalidArgument`) or over `MaxObjectSize`
  (`ErrTooLarge`). Entries that are deleted or have no kolo-log key on
  this peer cannot be read; the keyless ones are read again, in windows on
  several goroutines, when a `Get` or `Index` misses, so a replica reads its blobs as soon as the keys arrive.
  `Put` does not read them again, so it can append an object whose entry got its key since the last miss. Other
  entries in the log are ignored. `Index(ctx, h) (uint64, error)` returns
  the index of a live entry holding the object, or `ErrNotFound` when no
  entry holding it is live.
- `NewRemoteBackend(fetch, locate) *RemoteBackend` reads a content log
  on another peer, one entry per object. `locate(h) (uint64, bool)` maps
  an object hash to its entry index, from an object table the writer
  made with `Objects` and `Index`; `fetch(ctx, index) ([]byte, error)`
  gets that entry's value, checked by the transport, such as kolo-sync's
  `Fetch` with the entry's inclusion proof in a verified head, or its
  `FetchWithKeys` with entry keys the reader holds. An object
  `locate` does not know, and an entry that `fetch` reports deleted or
  keyless (`kololog.ErrDeleted`, `kololog.ErrKeyUnavailable`), is
  `ErrNotFound`; other fetch errors pass through wrapped. The Store still
  checks each object against its hash. `Put` returns `ErrReadOnly`. A
  range read through it fetches one entry for the root, one per node
  level and one per chunk under the range (`TestRemoteRangeRead` counts
  them over kolo-sync on 127.0.0.1).
- `ID` (a blob) and `Hash` (an object) are 32 bytes; `String()` is

## Reading from a pinning peer

To keep a blob on a pinning peer, add its log with `pin.Add`. A device
then reads it from the pinning peer in either of two ways, with the
blob's key and ID, the owner's public key and the content log's ID from
whoever shares the file:

- Whole log: `kolosync.Pull` into a kolo-store replica, then the entry
  keys from a peer with `kolosync.Keys` access, and `NewLogBackend` on the
  replica.
- Ranges, fetching only the entries a read needs: get the owner's head
  and the entry keys once from the owner (or any peer with `Keys` access)
  with `kolosync.FetchHead` and `kolosync.FetchKeys`, which sends no
  ciphertext, and keep both; later, with the owner offline, read from the
  pinning peer through a `RemoteBackend` whose fetch opens each entry with
  the key held locally:

  ```go
  // Once, owner online. first and last are the lowest and highest index in
  // the blob's object table. FetchKeys returns every key in first..last, so
  // it can cover the entries of other files and versions too; for scattered
  // entries, call it once per contiguous run of the table.
  head, err := kolosync.FetchHead(ctx, ownerConn, owner, contentLogID)
  if err != nil {
  	return err
  }
  keys, err := kolosync.FetchKeys(ctx, ownerConn, head, first, last)
  if err != nil {
  	return err
  }
  saved := head.Head().Encode() // keep it with the keys

  // Later, owner offline: check the saved head again; it is what every
  // entry from the pinning peer is checked against.
  h, err := kololog.DecodeHead(saved)
  if err != nil {
  	return err
  }
  if head, err = kololog.VerifyHead(owner, contentLogID, h); err != nil {
  	return err
  }
  fetch := func(ctx context.Context, i uint64) ([]byte, error) {
  	f, err := kolosync.FetchWithKeys(ctx, pinConn, head, i, i, func(j uint64) (kololog.EntryKey, error) {
  		if j < first || j-first >= uint64(len(keys)) {
  			return nil, nil // none held: kololog.ErrKeyUnavailable, then ErrNotFound
  		}
  		return bytes.Clone(keys[j-first]), nil // kolo-sync clears its copy after use
  	})
  	if err != nil {
  		return nil, err
  	}
  	return f[0].Data, f[0].Err // a one-entry range gives one Fetched or an error
  }
  blobs := koloblobs.New(koloblobs.NewRemoteBackend(fetch, locate)) // locate from the object table
  ```

  The entry keys stay on the reader: kolo-sync opens each entry locally,
  after the stream is closed, and sends no key to the pinning peer, which
  holds none either. Each entry is checked with its inclusion proof
  against the owner's signed head the reader kept, so a pinning peer
  behind that head is `kolosync.ErrBehind` and one with another history
  `kolosync.ErrDiverged`, and each object is checked against the blob's
  tree; a pinning peer that sends wrong, missing, extra, truncated or
  oversize answers, or a wrong head, stops the read but never makes it
  return wrong bytes. A held key that does not match its entry is
  `kolosync.ErrKeyMismatch`, which `RemoteBackend` returns wrapped; an
  entry with no held key is `ErrNotFound`. A blob version written after the
  saved head is past it: `FetchWithKeys` returns `kolosync.ErrInvalidArgument`
  wrapping `kololog.ErrOutOfRange`, which `RemoteBackend` returns wrapped,
  so a newer version needs a new head and its keys from the owner or a peer
  with `Keys` access. Keep the keys and the head as
  you keep other secrets at rest (encrypted, readable only by the
  reader), and clear the keys in memory only after every `Reader` that
  uses them is closed. Each fetch is one kolo-sync stream with a HEAD_REQ
  and a FETCH_REQ, so one round trip more than the object alone. What
  the pinning peer learns is listed under [What is visible to storage](#what-is-visible-to-storage).
  `TestPinDoubleNeverSeesAKey` shows that no key reaches the wire, and
  `TestPinRangeReadWithHeldKeys`, `TestPinNewerVersionNeedsNewHead` and
  `TestHostilePin` the rest.

## Errors

Errors, for `errors.Is`; none carries key bytes or content:

- `ErrNotFound`: the backend does not have an object of the blob (for a
  `LogBackend`, also a deleted or keyless entry; for a `RemoteBackend`, an
  object `locate` does not know, or an entry `fetch` reports deleted or
  keyless).
- `ErrCorrupt`: an object does not match its hash, is too small or too
  large, does not decrypt, or breaks a tree rule (see [formats](formats.md)).
- `ErrWrongKey`: the root does not open under the key or commits to
  another key. A non-root object given as an ID also reads as this.
- `ErrTooLarge`: a source longer than `MaxSize`, or an object over
  `MaxObjectSize` given to a `LogBackend`.
- `ErrReadOnly`: `Put` on a `RemoteBackend`, or on a `LogBackend` whose log
  cannot append.
- `ErrClosed`: a `Read`, `ReadAt` or `Seek` on a closed `Reader`.
- `ErrInvalidArgument`: a nil store, backend, log, source, context or
  fetch or locate function, a negative offset, an offset out of range for
  `Seek`, an unknown whence, or a `Put` whose hash is not the object's.
- Errors from the source and the backend are returned wrapped, and
  `ctx.Err()` when the context ends during `Write`.

## What is visible to storage

- Under one file key, equal chunks give equal ciphertext. Anyone who holds
  the objects (a `Backend`, a pinning peer, a copy of a disk) sees that two
  objects are equal, and so which chunks two versions share.
- On a raw `Backend`, exact object sizes (each chunk's size plus 48 bytes)
  and repeated hashes are visible, as is the number of objects per write.
  Only `LogBackend` pads: there each object is a kolo-log entry, encrypted
  again under an entry key the storage peer lacks and padded by kolo-log,
  so a pinning peer sees entry counts and padded sizes, and how many new
  entries each version adds.
- A peer serving kolo-sync `Fetch` or `FetchWithKeys` to a
  `RemoteBackend` sees the reader's kolo-secure identity, which entries it
  fetches and when, their ciphertext sizes, and the size of the head the
  reader checks against (each request carries it), which hints at when the
  reader got that head and links readers who got it together. From the
  order of the fetches (the root, one node per level, then the chunks) it
  learns the tree's shape, which blob is opened and which ranges of it are
  read. A read that stops after an entry also shows that something failed
  there, such as a held key that does not match. It never learns content
  or keys.
- Chunk sizes come from the keyed gear table. Under one key, someone who
  knows or chooses part of a file's content (and sees the resulting chunk
  sizes) may learn enough of the gear table to test guesses about other
  content under that key from its chunk sizes. Across keys the tables are
  unrelated.

## Tree, keys, resume and deletion

- Tree: 256-ary, built bottom-up while chunks arrive, every node but the
  last on its level full, so the shape follows from the chunk count. Each
  child entry is an object hash and the plaintext size under it. A file
  of up to 256 chunks has one node; 10 GiB (about 9000 chunks) has a root
  and about 36 nodes.
- ID: the SHA-256 of the root object. It commits to the key, the size,
  the shape and every chunk, comes from the content and the key only, and
  reveals nothing about the content without the key.
- Two layers of keys on kolo-log: kolo-log's entry keys protect each
  entry in transit and on every peer and travel only to peers with
  kolo-sync `Keys` access; the file key protects the blob and travels
  with the ID to those who may read the file. A pinning peer has
  neither: `TestPinStoreAndFetch` dumps its store and finds no file key,
  subkey, entry key, blob object or plaintext.
- Resume: a killed `Write` leaves whole entries only (kolo-store appends
  atomically and syncs), and running it again recomputes the same objects
  and appends the rest (`TestKillWriteResume` kills a writer process
  twice). A killed kolo-sync pull resumes from what the replica stored
  (`TestKillPullResume`); until then, objects that have not arrived read
  as `ErrNotFound`.
- Range reads fetch only the objects they need from the backend: from a
  peer through `RemoteBackend` and kolo-sync's ranged `Fetch` (or
  `FetchWithKeys` from a pinning peer), without
  replicating the log, or from a local log (after a `LogBackend`'s first
  scan of it, or through `RemoteBackend` with an object table). A whole
  log can still be pulled with kolo-sync `Pull` for offline use.
- Deletion: this library never deletes. A layer above that removes a blob
  deletes its log entries with kolo-log's `Delete`, which is a best-effort
  tombstone: it holds on peers that follow the protocol, and a peer that
  already has the entry key can keep the data. Objects of a write that was
  never completed stay in the log until then. Versions written under one
  key, and identical rewrites, share entries, so deleting one version's
  `Objects` breaks the others: delete only the entries that no kept blob
  under the key lists.
