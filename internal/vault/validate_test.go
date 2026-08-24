package vault

import (
	"strings"
	"testing"
)

func TestAVaultNameIsAnAsciiWordWithinTheLengthLimit(t *testing.T) {
	tests := []struct {
		name    string
		isValid bool
	}{
		{"myvault", true},
		{"my-vault", true},
		{"my_vault", true},
		{"vault123", true},
		{"", false},
		{"my vault", false},
		{"my.vault", false},
		{"vault/../../etc/passwd", false},
		{"vault!", false},
		{"café", false},
		// A name is bounded so that its filename, with a salt and a suffix,
		// fits within the 255 bytes most filesystems allow.
		{strings.Repeat("a", maxNameLen), true},
		{strings.Repeat("a", maxNameLen+1), false},
	}

	for _, tt := range tests {
		err := ValidateName(tt.name)
		if (err == nil) != tt.isValid {
			t.Errorf("ValidateName(%q) expected valid=%v, got err=%v", tt.name, tt.isValid, err)
		}
	}
}

func TestAPasswordNeedsEightCharactersAndNoNewline(t *testing.T) {
	tests := []struct {
		password string
		isValid  bool
	}{
		{"short", false},
		{"eightchr", true},
		{"longer-password", true},
		{"", false},
		{"1234567", false},
		{"12345678", true},
		// Characters, not bytes: eight of these take sixteen.
		{"\u00e1\u00e9\u00ed\u00f3\u00fa\u00f1\u00fc\u00f6", true},
		// A password file of several lines is a file of something else.
		{"abc\ndefghij", false},
		{"\n12345678", false},
		{"12345678\n", false},
	}

	for _, tt := range tests {
		err := ValidatePassword([]byte(tt.password))
		if (err == nil) != tt.isValid {
			t.Errorf("ValidatePassword(%q) expected valid=%v, got err=%v", tt.password, tt.isValid, err)
		}
	}
}

// A password long enough to pass the length rule but holding a newline is
// refused for the newline, so that the error names what is actually wrong with
// it rather than reporting a ten character password as too short.
func TestValidatePasswordNamesANewlineRatherThanTheLength(t *testing.T) {
	err := ValidatePassword([]byte("abc\ndefghij"))
	if err == nil {
		t.Fatal("expected a password holding a newline to be refused")
	}
	if !strings.Contains(err.Error(), "newline") {
		t.Errorf("expected the error to name the newline, got %q", err)
	}
}

func TestOnlyAFilenameCarryingASaltNamesAVault(t *testing.T) {
	const salt = testSalt
	tests := []struct {
		name    string
		isValid bool
	}{
		// A key is derived from the salt in the filename, so a name without
		// one names no vault this version of mrs can open.
		{"vault", false},
		{"vault." + salt, true},
		{"vault-1." + salt, true},
		{"vault." + salt + ".extra", false},
		{"vault.", false},
		{"." + salt, false},
		{"invalid name." + salt, false},
		{"vault.invalid salt!", false},
		// A salt-shaped segment is required, so unrelated files in the vault
		// directory are not mistaken for vaults.
		{"README.md", false},
		{"notes.txt", false},
		{"vault.tooshort", false},
		{"vault." + salt + "0", false},
	}

	for _, tt := range tests {
		err := validateFilename(tt.name)
		if (err == nil) != tt.isValid {
			t.Errorf("validateFilename(%q) expected valid=%v, got err=%v", tt.name, tt.isValid, err)
		}
	}
}
