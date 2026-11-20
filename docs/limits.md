# Limits

This page is reference material: the README does not repeat it.

## Format constants

Limits fixed by the format:

| Constant | Value | Why |
|---|---|---|
| `MaxObjectSize` | 4,128,764 bytes | the largest kolo-log entry value that kolo-sync carries, so every object syncs |
| `ObjectOverhead` | 48 bytes | content MAC (32) and GCM tag (16) per object |
| `MaxChunkSize` | 4,128,716 bytes | `MaxObjectSize - ObjectOverhead`; a chunk is cut here when no cut point is found |
| `MinChunkSize` | 262,144 bytes | the chunker's minimum; only a blob's last chunk is smaller |
| average chunk | about 1 MiB (1.19 MB measured) | half the new bytes of a 2 MiB average on scattered edits |
| `Fanout` | 256 children per node | a node is about 10 KiB, about 1% of the chunks it covers |
| `MaxHeight` | 6 levels | 256^6 minimum-size chunks exceed `MaxSize`, so no honest tree is taller |
| `MaxSize` | 2^63 - 1 bytes | Go's `io.Seeker` offsets |

None of these is a product limit: a file of any size up to Go's own
offset limit is stored, as many chunks and nodes as it needs. They are
format constants, not settings, because each follows from something
outside this library: the chunk and object sizes from the kolo-sync entry
cap, the fanout from the node size that keeps range reads cheap, the
height from the fanout and the largest size, the largest size from
`io.Seeker`. Changing one would change every ID. They also bound hostile
input: a reader checks each object's size against `MaxObjectSize` before
it decrypts, and a hostile tree can neither nest deeper than `MaxHeight`
nor list more than `Fanout` children, so a read's work and memory follow
from the bytes asked for. `Objects` is the exception: it lists what the
root claims, bounded only by `MaxSize`, so it takes a context for blobs
from writers you do not trust.

## Memory

Memory: `Write` runs the chunker, 2 sealing goroutines and the backend's
`Put` as a pipeline, so it holds at most `workers + 3` chunks in flight (5),
each a plaintext buffer and an object buffer (a buffer over 2 MiB is dropped
after its chunk, so they stay near the average chunk, 1 MiB, not the largest, at
most `MaxChunkSize` and `MaxObjectSize`), plus the chunker's buffer and one
pending node per tree level. A `Reader` holds the
nodes on the path to its last chunk and that chunk's plaintext. Neither
depends on the file size: `TestHugeFileBoundedMemory` writes and reads
back a generated 10 GiB file, every chunk verified, with a 54 MiB peak heap
and an 84 MiB peak resident size under `GOMEMLIMIT=64MiB`. A `LogBackend`
adds its index, which grows with the log and is not bounded: about 140 bytes of heap per entry (a 32-byte hash, a slice and
a map slot; 142 bytes measured for 1 million entries), so a log of 10 million entries from a peer you do not
trust costs about 1.4 GB once indexed. While it indexes a log it reads up to 4 entries at once, each held
decrypted until hashed. Entries without a key are read again, in the same windows, only when a lookup misses
(and `Put` never reads them again), so a log of many of them costs a `Get` of an unknown hash one pass over them, not every `Put`.
kolo-store reads entries from disk on demand, so the same holds for a
blob in a log on Pebble: `TestPebbleHugeFileBoundedMemory` writes a
generated 10 GiB file into a kolo-store log on Pebble, opens the store
again and reads it back, with an 82 MiB peak heap and a 173 MiB peak
resident size under `GOMEMLIMIT=64MiB`, about the heap of a 2 GiB file
(Pebble's memtable is most of it). That test uses about 10.2 GiB of
temporary disk, removed after.

## Benchmarks

Apple M5 (arm64), Go 1.27.3, one core per operation, median of three
runs of `go test -bench .` (other test jobs were running on the machine):

| Benchmark | Result |
|---|---|
| `Write`, 256 MiB, objects dropped, one sealing goroutine | 848 MB/s |
| `Write`, 256 MiB, objects dropped, 2 to 8 sealing goroutines (the default is 2) | 2150 MB/s, the speed of the chunker, which is one goroutine (`BenchmarkWriteWorkers`) |
| `Read`, 256 MiB sequential, every object verified (hash, GCM, content MAC) | 1277 MB/s |
| `ReadAtRandom`, 4 KiB at a random offset | 0.94 ms (fetches and verifies a 1.2 MB chunk) |
| `Chunker` alone | 2294 MB/s |
| `LogBackendWrite`, 64 MiB into a kolo-store log in memory | 269 MB/s |
| `LogBackendWrite`, 64 MiB into a kolo-store log on Pebble | 69 MB/s (each entry signed and synced) |
| 10 GiB into a kolo-store log on Pebble, store reopened, read back | 173 s write, 59 s read, 82 MiB peak heap, 173 MiB peak RSS (the write syncs the disk at every entry, and other jobs were running) |
| 10 GiB write then read, generated source | 5.9 s write, 15.2 s read (the test backend re-encrypts each chunk it serves), 54 MiB peak heap |

Overhead: objects add 0.007% to the plaintext (48 bytes per chunk and
the nodes); stored as kolo-log entries the total is 1.2% to 1.4%, mostly
kolo-log's padding of each entry.
