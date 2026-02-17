package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/gtank/cryptopasta"
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
	// Use subtle.ConstantTimeByteEq to prevent compiler from optimizing away the loop
	// Actually, filling with 0 is standard.
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

	decrypted, err := cryptopasta.Decrypt(data, k)
	if err == nil {
		return decrypted, nil
	}

	// Fallback to legacy iterations
	kLegacy, err := key(password, salt, LegacyIterations)
	if err != nil {
		return nil, err
	}
	defer Wipe(kLegacy[:])

	return cryptopasta.Decrypt(data, kLegacy)
}

// Encrypt returns encrypted data.
func Encrypt(data []byte, password []byte, salt string) ([]byte, error) {
	k, err := key(password, salt, CurrentIterations)
	if err != nil {
		return nil, err
	}
	defer Wipe(k[:])
	return cryptopasta.Encrypt(data, k)
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
		return nil, fmt.Errorf("Salt must be at least %d in length, but was %d", minSaltLen, len(salt))
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
