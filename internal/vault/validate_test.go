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
		err := validateName(tt.name)
		if (err == nil) != tt.isValid {
			t.Errorf("validateName(%q) expected valid=%v, got err=%v", tt.name, tt.isValid, err)
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

func TestValidateNameWithOptionalSalt(t *testing.T) {
	tests := []struct {
		name    string
		isValid bool
	}{
		{"vault", true},
		{"vault.salt", true},
		{"vault.salt.extra", false},
		{"vault.", false},
		{".salt", false},
		{"invalid name.salt", false},
		{"vault.invalid salt!", false},
	}

	for _, tt := range tests {
		err := validateNameWithOptionalSalt(tt.name)
		if (err == nil) != tt.isValid {
			t.Errorf("validateNameWithOptionalSalt(%q) expected valid=%v, got err=%v", tt.name, tt.isValid, err)
		}
	}
}
