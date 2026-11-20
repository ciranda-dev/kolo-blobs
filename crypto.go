package koloblobs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Labels of the three object kinds, one per type, in the content MAC input and as GCM additional data.
const (
	labelChunk = "kolo-blobs/chunk/v0"
	labelNode  = "kolo-blobs/node/v0"
	labelRoot  = "kolo-blobs/root/v0"
	commitCtx  = "kolo-blobs/key/v0"
)

var zeroNonce [12]byte

// keys are the subkeys of one file key.
type keys struct {
	macKey, enc [32]byte // content MAC key and object-key derivation key
	commit      [32]byte
	gear        [256]uint64
}

func deriveKeys(k Key) (*keys, error) {
	ks := new(keys)
	for _, d := range []struct {
		info string
		out  []byte
	}{{"kolo-blobs/content-mac/v0", ks.macKey[:]}, {"kolo-blobs/enc/v0", ks.enc[:]}} {
		b, err := hkdf.Expand(sha256.New, k[:], d.info, 32)
		if err != nil {
			ks.zero()
			return nil, fmt.Errorf("koloblobs: derive keys: %w", err)
		}
		copy(d.out, b)
		clear(b)
	}
	g, err := hkdf.Expand(sha256.New, k[:], "kolo-blobs/gear/v0", 8*256)
	if err != nil {
		ks.zero()
		return nil, fmt.Errorf("koloblobs: derive keys: %w", err)
	}
	for i := range ks.gear {
		ks.gear[i] = binary.LittleEndian.Uint64(g[8*i:])
	}
	clear(g)
	h := sha256.New()
	h.Write([]byte(commitCtx))
	h.Write(k[:])
	h.Sum(ks.commit[:0])
	return ks, nil
}

func (ks *keys) zero() { *ks = keys{} }

// objectAEAD returns the AES-256-GCM of the object whose content MAC is s: its key is HMAC-SHA256(enc, s).
func (ks *keys) objectAEAD(s []byte) (cipher.AEAD, error) {
	m := hmac.New(sha256.New, ks.enc[:])
	m.Write(s)
	var k [32]byte
	m.Sum(k[:0])
	c, err := aes.NewCipher(k[:])
	clear(k[:])
	if err != nil {
		return nil, fmt.Errorf("koloblobs: object cipher: %w", err)
	}
	a, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("koloblobs: object cipher: %w", err)
	}
	return a, nil
}

// contentMAC returns s = HMAC-SHA256(macKey, uvarint(len(label)) ‖ label ‖ p), appended to dst; the length
// prefix keeps label and plaintext apart for any set of labels.
func (ks *keys) contentMAC(dst []byte, label string, p []byte) []byte {
	m := hmac.New(sha256.New, ks.macKey[:])
	m.Write(binary.AppendUvarint(nil, uint64(len(label))))
	m.Write([]byte(label))
	m.Write(p)
	return m.Sum(dst)
}

// seal appends to dst the object of plaintext p: s ‖ AES-256-GCM(HMAC(enc, s), 0, p, label), where s is
// the content MAC, stored as the object's first 32 bytes.
func (ks *keys) seal(dst []byte, label string, p []byte) ([]byte, error) {
	dst = ks.contentMAC(dst, label, p)
	a, err := ks.objectAEAD(dst[len(dst)-sha256.Size:])
	if err != nil {
		return nil, err
	}
	return a.Seal(dst, zeroNonce[:], p, []byte(label)), nil
}

// errAuth is returned by open for an object that does not authenticate under the key and label.
var errAuth = errors.New("koloblobs: object does not authenticate")

// open decrypts obj into dst[:0]; obj has at least ObjectOverhead bytes. It returns errAuth if GCM
// refuses the object, and ErrCorrupt if the stored s is not the content MAC of the plaintext, so every
// plaintext has exactly one object.
func (ks *keys) open(dst []byte, label string, obj []byte) ([]byte, error) {
	a, err := ks.objectAEAD(obj[:sha256.Size])
	if err != nil {
		return nil, err
	}
	p, err := a.Open(dst[:0], zeroNonce[:], obj[sha256.Size:], []byte(label))
	if err != nil {
		return nil, errAuth
	}
	var s [sha256.Size]byte
	if !hmac.Equal(ks.contentMAC(s[:0], label, p), obj[:sha256.Size]) {
		clear(p)
		return nil, fmt.Errorf("%w: content MAC does not match the plaintext", ErrCorrupt)
	}
	return p, nil
}
