package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/gtank/cryptopasta"
	"golang.org/x/crypto/pbkdf2"
)

const minSaltLen = 32

// Decrypt returns decrypted data.
func Decrypt(data []byte, password string, salt string) ([]byte, error) {
	k, err := key(password, salt)
	if err != nil {
		return nil, err
	}
	return cryptopasta.Decrypt(data, k)
}

// Encrypt returns encrypted data.
func Encrypt(data []byte, password string, salt string) ([]byte, error) {
	k, err := key(password, salt)
	if err != nil {
		return nil, err
	}
	return cryptopasta.Encrypt([]byte(data), k)
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

func key(password string, salt string) (*[32]byte, error) {
	if len(salt) < minSaltLen {
		return nil, fmt.Errorf("Salt must be at least %d in length, but was %d", minSaltLen, len(salt))
	}
	var arr [32]byte
	k := pbkdf2.Key([]byte(password), []byte(salt), 4096, 32, sha256.New)
	copy(arr[:], k)
	return &arr, nil
}
