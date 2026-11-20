# Formats

Object and node formats, the encryption design and the references.

## Objects and nodes

Objects, the values of a `Backend` (and of the log entries of a
`LogBackend`):

    s (32) ‖ AES-256-GCM(k, nonce 0, plaintext, AD label)

Labels: `kolo-blobs/chunk/v0`, `kolo-blobs/node/v0`, `kolo-blobs/root/v0`.
`s` is HMAC-SHA256 under the content MAC key of uvarint(length of the
label) ‖ label ‖ plaintext; `k` is HMAC-SHA256 under the object key of
`s`. Subkeys: HKDF-Expand(SHA-256, K, `kolo-blobs/content-mac/v0`, 32),
(…, `kolo-blobs/enc/v0`, 32) and (…, `kolo-blobs/gear/v0`, 2048), the last
as 256 little-endian 64-bit words. A chunk's plaintext is the file's bytes.
Node plaintexts, in [kolo-codec](https://github.com/ciranda-dev/kolo-codec)
form:

    root:  commitment (32) ‖ uvarint(height 1..6) ‖ uvarint(n) ‖ n × (hash (32) ‖ uvarint(size))
    inner: uvarint(height) ‖ uvarint(n) ‖ n × (hash (32) ‖ uvarint(size))

A child of a height 1 node is a chunk, of a higher node a node one level
lower. `size` is the plaintext bytes under the child. A reader refuses,
with `ErrCorrupt`: non-minimal varints, trailing bytes, a height of 0 or
above 6 or not one less than the parent's, more than 256 children, no
child (except an empty blob's root of height 1), one child in a root
above height 1, fewer than 256 children in a node that is not the last
of its level, a size of 0, a chunk over `MaxChunkSize`, a chunk under
`MinChunkSize` that is not the blob's last, children whose sizes do not
add up to what the parent says, a total over `MaxSize`, and a chunk that
does not decrypt to exactly its size. There is no JSON form.

## Design

- Chunks: content-defined (FastCDC: a gear hash, cut-point skipping below
  the minimum, a harder mask before the 1 MiB average and an easier one
  after). Measured on a 161 MiB tar of a source tree with one file grown
  by 1 KiB, the second version stores 1.4% new bytes, against 56% with
  fixed chunks; an insertion in the middle of 1 GiB stores 0.1% against
  50%. The gear table is derived from the file key, so cut points differ
  between keys and chunk sizes under one key cannot be matched against a
  known file chunked under another key.
- Encryption: deterministic encryption with a content-derived key. Per
  file key `K`, HKDF-SHA256 derives a content MAC key, an object key and
  the gear table. An object with plaintext `P` and type label `L` is
  `s ‖ AES-256-GCM(k, nonce 0, P, AD L)`, where
  `s = HMAC-SHA256(content MAC key, uvarint(len(L)) ‖ L ‖ P)` is stored
  as the object's first 32 bytes and `k = HMAC-SHA256(object key, s)`.
  Each derived key encrypts one plaintext only, so the fixed nonce is
  never reused with another message; AES-256-GCM provides authenticity.
  On open the reader recomputes `s` from the decrypted plaintext and
  refuses a mismatch (`ErrCorrupt`), so every plaintext has exactly one
  object. Each object type (chunk, node, root) has its own label, and an
  object of one type never opens as another. The root holds
  `SHA-256("kolo-blobs/key/v0" ‖ K)`, checked on open, so an ID opens
  under one key only.
- Dedup stays inside one key. Without the key nobody can compute an
  object, its hash or its cut points for a guessed file, so convergent
  encryption's confirmation-of-a-file and learn-the-rest attacks do not
  apply to outsiders. Under one key, equal chunks are stored once: a
  resumed write stores nothing twice, and versions written with the
  file's key share their unchanged chunks. Different keys never share an
  object. A reader with a key can read every blob written with it.

## References

- NIST [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) (2015).
  Takes: SHA-256, for object hashes, IDs and the key commitment. Chosen over BLAKE2b (1479 MB/s against 3204 MB/s
  here, with CPU instructions on arm64 and amd64); BLAKE3 is in neither the standard library nor golang.org/x/crypto.
  Not implemented: nothing left out.
- [RFC 2104, HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/info/rfc2104) (Informational, February 1997).
  Takes: HMAC-SHA256, for the content MAC and the per-object keys.
  Not implemented: nothing left out.
- [RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/info/rfc5869) (Informational, May 2010).
  Takes: HKDF-SHA256, for the subkeys of a file key.
  Not implemented: nothing left out.
- NIST [SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D) (2007), GCM.
  Takes: AES-256-GCM, for object encryption and authenticity, chosen over XChaCha20-Poly1305 for speed (8611 against
  1380 MB/s here).
  Not implemented: random nonces. Each object has its own derived key and a fixed nonce.
- Xia et al., [FastCDC: A Fast and Efficient Content-Defined Chunking Approach for Data Deduplication](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia), USENIX ATC 2016.
  Takes: the gear hash, cut-point skipping and normalized chunking, for the chunker.
  Not implemented: the fixed gear table. The gear table is derived from the file key.
- Not SIV: neither [RFC 5297, SIV Authenticated Encryption Using AES](https://www.rfc-editor.org/info/rfc5297) (Informational, October 2008)
  nor [RFC 8452, AES-GCM-SIV](https://www.rfc-editor.org/info/rfc8452) (Informational, April 2019) is claimed.
