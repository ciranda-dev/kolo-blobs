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
