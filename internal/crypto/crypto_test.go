package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	password := "super-secret-password"
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

	if !bytes.Equal(data, decrypted) {
		t.Errorf("decrypted data does not match original; expected %q, got %q", string(data), string(decrypted))
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	password := "correct-password"
	wrongPassword := "wrong-password"
	salt, _ := Salt()
	data := []byte("sensitive info")

	encrypted, _ := Encrypt(data, password, salt)

	_, err := Decrypt(encrypted, wrongPassword, salt)
	if err == nil {
		t.Error("decryption should have failed with wrong password")
	}
}

func TestDecryptWithWrongSalt(t *testing.T) {
	password := "password"
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
	if len(s1) < minSaltLen {
		t.Errorf("salt too short: got %d, want at least %d", len(s1), minSaltLen)
	}

	s2, _ := Salt()
	if s1 == s2 {
		t.Error("Salt() should return unique salts")
	}
}
