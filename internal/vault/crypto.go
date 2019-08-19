package vault

import (
	"crypto/sha256"

	"github.com/gtank/cryptopasta"
	"golang.org/x/crypto/pbkdf2"
)

const salt = "99daa49d-3a53-4bf8-a74a-93295de71d41-4bac-8cea"

func key(password string) *[32]byte {
	var arr [32]byte
	k := pbkdf2.Key([]byte(password), []byte(salt), 4096, 32, sha256.New)
	copy(arr[:], k)
	return &arr
}

func decrypt(data []byte, password string) ([]byte, error) {
	return cryptopasta.Decrypt(data, key(password))
}

func encrypt(data []byte, password string) ([]byte, error) {
	return cryptopasta.Encrypt([]byte(data), key(password))
}
