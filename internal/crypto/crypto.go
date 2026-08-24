package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	minSaltLen = 32
	// CurrentIterations is the only iteration count mrs derives a key with. A
	// vault written by a release that used fewer is not read: a fallback opens
	// it at that weaker derivation for as long as it goes unsaved, which is
	// indefinitely for a vault nobody edits.
	CurrentIterations = 600000
)

// Wipe fills the given byte slice with zeros to clear sensitive data from memory.
func Wipe(buf []byte) {
	if buf == nil {
		return
	}
	for i := range buf {
		buf[i] = 0
	}
}

// Decrypt returns decrypted data.
func Decrypt(data []byte, password []byte, salt string) ([]byte, error) {
	k, err := key(password, salt, CurrentIterations)
	if err != nil {
		return nil, err
	}
	defer Wipe(k[:])
	return open(data, k)
}

// oldIterations is the count mrs derived a key with before CurrentIterations. A
// key is derived at it only to tell one failure apart from another, and what it
// opens is discarded, so no vault is ever read at a derivation weaker than the
// one mrs writes.
const oldIterations = 4096

// SealedAtOldIterations reports whether the given password opens the data at
// the iteration count mrs used before CurrentIterations. A caller asks after a
// decryption has already failed, so that the owner of an old vault is not told
// what someone who mistyped a password is told: the password is right and the
// vault is recoverable, by a release that still reads it.
//
// Its argument order matches Decrypt and Encrypt above, which it is asked
// alongside.
func SealedAtOldIterations(data []byte, password []byte, salt string) bool {
	k, err := key(password, salt, oldIterations)
	if err != nil {
		return false
	}
	defer Wipe(k[:])
	plaintext, err := open(data, k)
	if err != nil {
		return false
	}
	Wipe(plaintext)
	return true
}

// Encrypt returns encrypted data.
func Encrypt(data []byte, password []byte, salt string) ([]byte, error) {
	k, err := key(password, salt, CurrentIterations)
	if err != nil {
		return nil, err
	}
	defer Wipe(k[:])
	return seal(data, k)
}

// seal and open are copied from github.com/gtank/cryptopasta (encrypt.go, as
// of commit 1f550f6f2f69), whose author dedicated it to the public domain
// under CC0 with the stated intent that it be copied into a caller rather than
// imported. It has had no commits since 2017, so it is vendored here instead
// of depended on. The construction is 256-bit AES-GCM under a random 96-bit
// nonce, written as nonce|ciphertext|tag, and every vault already written is
// in that format: changing it is a change of file format and needs a way to
// migrate. A defect in these functions is worth fixing here; a different
// construction is worth taking from a reviewed library.
//
// seal encrypts with 256-bit AES-GCM under a nonce generated per call, which
// must never repeat under one key. That holds here because a vault is
// rewritten in full on every save rather than appended to.
func seal(plaintext []byte, k *[32]byte) ([]byte, error) {
	gcm, err := newGCM(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Sealing into nonce prefixes it to the output, which is the layout open
	// reads back.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// open decrypts what seal produced, and reports an error for ciphertext that
// was altered as surely as for the wrong key: GCM authenticates before it
// returns any plaintext.
func open(ciphertext []byte, k *[32]byte) ([]byte, error) {
	gcm, err := newGCM(k)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(ciphertext) < n {
		return nil, errors.New("malformed ciphertext")
	}
	return gcm.Open(nil, ciphertext[:n], ciphertext[n:], nil)
}

func newGCM(k *[32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Salt returns a randomly generated salt.
// Derived from: https://github.com/golang/crypto/blob/eec23a3978adcfd26c29f4153eaa3e3d9b2cc53a/bcrypt/bcrypt.go#L144
func Salt() (string, error) {
	unencodedSalt := make([]byte, minSaltLen)
	_, err := io.ReadFull(rand.Reader, unencodedSalt)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(unencodedSalt)[:minSaltLen], nil
}

func key(password []byte, salt string, iterations int) (*[32]byte, error) {
	if len(salt) < minSaltLen {
		return nil, fmt.Errorf("salt must be at least %d characters, but was %d", minSaltLen, len(salt))
	}
	var arr [32]byte
	k := pbkdf2.Key(password, []byte(salt), iterations, 32, sha256.New)
	copy(arr[:], k)
	Wipe(k)
	return &arr, nil
}

// SecureCompare performs a constant time comparison of two byte slices.
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
