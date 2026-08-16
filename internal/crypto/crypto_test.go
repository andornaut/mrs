package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	password := []byte("super-secret-password")
	defer Wipe(password)
	salt, err := Salt()
	if err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}

	data := []byte("hello world")

	encrypted, err := Encrypt(data, password, salt)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if bytes.Equal(data, encrypted) {
		t.Error("encrypted data should not match original data")
	}

	decrypted, err := Decrypt(encrypted, password, salt)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	defer Wipe(decrypted)

	if !bytes.Equal(data, decrypted) {
		t.Errorf("decrypted data does not match original; expected %q, got %q", string(data), string(decrypted))
	}
}

func TestLegacyDecrypt(t *testing.T) {
	password := []byte("password")
	defer Wipe(password)
	salt, _ := Salt()
	data := []byte("legacy data")

	// Encrypted as an older version of mrs would have, so that Decrypt has to
	// fall back to the old iteration count to read it.
	k, _ := key(password, salt, LegacyIterations)
	defer Wipe(k[:])
	encrypted, _ := seal(data, k)

	decrypted, err := Decrypt(encrypted, password, salt)
	if err != nil {
		t.Fatalf("Legacy decryption failed: %v", err)
	}
	defer Wipe(decrypted)

	if !bytes.Equal(data, decrypted) {
		t.Errorf("Legacy decrypted data does not match original; expected %q, got %q", string(data), string(decrypted))
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	password := []byte("correct-password")
	defer Wipe(password)
	wrongPassword := []byte("wrong-password")
	defer Wipe(wrongPassword)
	salt, _ := Salt()
	data := []byte("sensitive info")

	encrypted, _ := Encrypt(data, password, salt)

	_, err := Decrypt(encrypted, wrongPassword, salt)
	if err == nil {
		t.Error("decryption should have failed with wrong password")
	}
}

func TestDecryptWithWrongSalt(t *testing.T) {
	password := []byte("password")
	defer Wipe(password)
	salt1, _ := Salt()
	salt2, _ := Salt()
	data := []byte("sensitive info")

	encrypted, _ := Encrypt(data, password, salt1)

	_, err := Decrypt(encrypted, password, salt2)
	if err == nil {
		t.Error("decryption should have failed with wrong salt")
	}
}

func TestSalt(t *testing.T) {
	s1, err := Salt()
	if err != nil {
		t.Fatalf("Salt() error: %v", err)
	}
	// Exactly, not at least: a vault's filename is <name>.<salt>, and a salt of
	// any other length is not recognised as one.
	if len(s1) != minSaltLen {
		t.Errorf("salt length = %d, want %d", len(s1), minSaltLen)
	}

	s2, _ := Salt()
	if s1 == s2 {
		t.Error("Salt() should return unique salts")
	}
}

func TestWipe(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5}
	Wipe(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("byte at index %d was not wiped: %d", i, b)
		}
	}
}
