package koloblobs_test

import (
	"bytes"
	"context"
	"crypto/ed25519"

	koloblobs "github.com/ciranda-dev/kolo-blobs"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// Reading a blob range by range from a pinning peer with the entry keys held locally, as in the README.
func ExampleNewRemoteBackend_pin() {
	var (
		ctx                context.Context
		ownerConn, pinConn *kolosecure.Conn
		owner              ed25519.PublicKey
		contentLogID       kololog.LogID
		first, last        uint64
		locate             koloblobs.LocateFunc
	)
	_ = func() error {
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
		_ = blobs
		return nil
	}
}
