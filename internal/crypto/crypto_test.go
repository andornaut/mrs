package crypto

import (
	"bytes"
	"testing"
)

func TestWhatEncryptSealsDecryptOpens(t *testing.T) {
	t.Parallel()
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

// Decrypt derives a key one way only. A vault sealed under the 4,096 iterations
// an older release used is not read back, so that no vault is opened at a key
// derivation weaker than the one mrs writes.
func TestDecryptRefusesTheOldIterationCount(t *testing.T) {
	t.Parallel()
	password := []byte("password")
	defer Wipe(password)
	salt, _ := Salt()
	data := []byte("old data")

	k, err := key(password, salt, 4096)
	if err != nil {
		t.Fatalf("failed to derive the fixture key: %v", err)
	}
	defer Wipe(k[:])
	encrypted, err := seal(data, k)
	if err != nil {
		t.Fatalf("failed to seal the fixture: %v", err)
	}

	if _, err := Decrypt(encrypted, password, salt); err == nil {
		t.Fatal("expected Decrypt() to refuse a vault sealed at the old iteration count")
	}

	// Refused, but told apart from a wrong password, which is the same failure
	// to AES-GCM and the wrong thing to tell the owner of a vault they can
	// still recover.
	if !SealedAtOldIterations(encrypted, password, salt) {
		t.Error("expected the old iteration count to be recognised")
	}
	if SealedAtOldIterations(encrypted, []byte("a different password"), salt) {
		t.Error("expected a wrong password to be recognised as nothing of the kind")
	}
}

// A vault mrs wrote itself is not mistaken for one at the old count, whatever
// password is offered for it.
func TestCurrentCiphertextIsNotTakenForTheOldIterationCount(t *testing.T) {
	t.Parallel()
	password := []byte("password")
	defer Wipe(password)
	salt, _ := Salt()

	encrypted, err := Encrypt([]byte("data"), password, salt)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	if SealedAtOldIterations(encrypted, password, salt) {
		t.Error("expected a current vault not to be reported as an old one")
	}
	if SealedAtOldIterations(encrypted, []byte("a different password"), salt) {
		t.Error("expected a current vault not to be reported as an old one")
	}
}

func TestAWrongPasswordDoesNotDecrypt(t *testing.T) {
	t.Parallel()
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

func TestAWrongSaltDoesNotDecrypt(t *testing.T) {
	t.Parallel()
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

func TestEverySaltIsNewAndOfTheLengthAFilenameCarries(t *testing.T) {
	t.Parallel()
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

// SecureCompare answers whether two passwords typed at a prompt agree, which is
// the only thing standing between a typo and a vault encrypted under a password
// its owner does not know. Its one job is to say no to everything but an exact
// match, whatever the two differ by.
func TestOnlyAnExactMatchIsAcceptedAsTheSamePassword(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		a, b string
		want bool
	}{
		"the same":            {"a password", "a password", true},
		"both empty":          {"", "", true},
		"entirely different":  {"a password", "something else", false},
		"one character apart": {"a password", "a passwore", false},
		"a prefix":            {"a password", "a passwor", false},
		"a trailing space":    {"a password", "a password ", false},
		"differing case":      {"a password", "A Password", false},
		"one empty":           {"a password", "", false},
	}
	for desc, tt := range tests {
		t.Run(desc, func(t *testing.T) {
			if got := SecureCompare([]byte(tt.a), []byte(tt.b)); got != tt.want {
				t.Errorf("SecureCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestWipingLeavesEveryByteZero(t *testing.T) {
	t.Parallel()
	buf := []byte{1, 2, 3, 4, 5}
	Wipe(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("byte at index %d was not wiped: %d", i, b)
		}
	}
}
