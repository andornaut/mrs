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
	minSaltLen        = 32
	LegacyIterations  = 4096
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
	// Try the current (new) iterations first
	k, err := key(password, salt, CurrentIterations)
	if err != nil {
		return nil, err
	}
	defer Wipe(k[:])

	decrypted, err := open(data, k)
	if err == nil {
		return decrypted, nil
	}

	// Fallback to legacy iterations
	kLegacy, err := key(password, salt, LegacyIterations)
	if err != nil {
		return nil, err
	}
	defer Wipe(kLegacy[:])

	return open(data, kLegacy)
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
// of depended on. Do not change the construction: 256-bit AES-GCM under a
// random 96-bit nonce, written as nonce|ciphertext|tag. Every existing vault
// is in this format, and any replacement belongs in a reviewed library rather
// than in an edit to these functions.
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
