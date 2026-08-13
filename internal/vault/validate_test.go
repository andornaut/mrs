package vault

import (
	"testing"
)

func TestValidateName(t *testing.T) {
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
	}

	for _, tt := range tests {
		err := ValidateName(tt.name)
		if (err == nil) != tt.isValid {
			t.Errorf("ValidateName(%q) expected valid=%v, got err=%v", tt.name, tt.isValid, err)
		}
	}
}

func TestValidatePassword(t *testing.T) {
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
	}

	for _, tt := range tests {
		err := validatePassword([]byte(tt.password))
		if (err == nil) != tt.isValid {
			t.Errorf("validatePassword(%q) expected valid=%v, got err=%v", tt.password, tt.isValid, err)
		}
	}
}

func TestValidateFilename(t *testing.T) {
	const salt = "12345678901234567890123456789012" // 32 characters, as crypto.Salt() returns
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
