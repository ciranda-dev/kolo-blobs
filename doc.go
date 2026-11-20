// Package koloblobs stores files as encrypted, content-addressed blobs for Kolo: the content layer under
// kolo-files, with no names, folders or versions.
//
// Write cuts a file into content-defined chunks, encrypts each under keys derived from a random per-file
// key, builds a Merkle tree over them and returns the blob's ID, the hash of the tree's root. Open returns
// a Reader that checks every chunk against the tree while it streams, and reads any range by fetching only
// the chunks that cover it. Objects live in a Backend; LogBackend keeps them as kolo-log entries, so blobs
// travel with kolo-sync and rest on kolo-pin pinning peers, which hold only ciphertext and never a key.
//
// Experimental: the API may change before v1.0.0.
package koloblobs
