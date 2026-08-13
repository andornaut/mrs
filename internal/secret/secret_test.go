package secret

import (
	"regexp"
	"testing"

	"github.com/andornaut/mrs/internal/crypto"
)

func TestTranscribe(t *testing.T) {
	// Every line is a line of secrets, including one that begins with a "#".
	// Only mrs's own instructions are removed, and only by stripInstructions.
	input := `
Key1
Value1
More Value1

Key2
#Value2

Key3
Value3
`
	b, err := parseSecrets([]byte(input))
	if err != nil {
		t.Fatalf("parseSecrets failed: %v", err)
	}

	if b.Len() != 3 {
		t.Errorf("expected 3 secrets, got %d", b.Len())
	}

	expectedKeys := []string{"Key1", "Key2", "Key3"}
	for i, key := range expectedKeys {
		if string(b.secrets[i].Key()) != key {
			t.Errorf("expected key %d to be %q, got %q", i, key, b.secrets[i].Key())
		}
	}
	if got := string(b.secrets[1]); got != "Key2\n#Value2\n" {
		t.Errorf("expected a value beginning with # to be kept, got %q", got)
	}
}

func TestTranscribePreservesWhitespaceWithinSecrets(t *testing.T) {
	input := "Key1\n  indented\ntrailing   \n\nKey2\nValue2\n"
	b, err := parseSecrets([]byte(input))
	if err != nil {
		t.Fatalf("parseSecrets failed: %v", err)
	}
	if got, expected := string(b.secrets[0]), "Key1\n  indented\ntrailing   \n"; got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestStripInstructions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "the instructions mrs prepends",
			input:    instructions + "Key1\nValue1\n",
			expected: "Key1\nValue1\n",
		},
		{
			name:     "instructions the user partly deleted",
			input:    instructionLines[1] + "\n\nKey1\nValue1\n",
			expected: "Key1\nValue1\n",
		},
		{
			name:     "a comment of the user's own is kept",
			input:    instructions + "# my own note\nKey1\nValue1\n",
			expected: "# my own note\nKey1\nValue1\n",
		},
		{
			// An editor opens with the cursor on the first line, so this is
			// what typing straight into an `mrs add` session produces.
			name:     "instructions the user typed above",
			input:    "Key1\nValue1\n" + instructions,
			expected: "Key1\nValue1\n\n",
		},
		{
			name:     "instructions left in the middle",
			input:    "Key1\nValue1\n\n" + instructions + "Key2\nValue2\n",
			expected: "Key1\nValue1\n\n\nKey2\nValue2\n",
		},
		{
			name:     "content that begins with a blank line",
			input:    instructions + "\n\nKey1\nValue1\n",
			expected: "Key1\nValue1\n",
		},
		{
			name:     "no instructions at all",
			input:    "Key1\nValue1\n",
			expected: "Key1\nValue1\n",
		},
		{
			name:     "nothing but instructions",
			input:    instructions,
			expected: "",
		},
		{
			name:     "an empty session",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(stripInstructions([]byte(tt.input))); got != tt.expected {
				t.Errorf("stripInstructions() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestSecretListSearch(t *testing.T) {
	secrets := []secret{
		secret(`Apple
color: red`),
		secret(`Banana
color: yellow`),
		secret(`Cherry
color: red`),
	}
	b := newSecretList(secrets)

	// Search by key
	re1 := regexp.MustCompile("(?i)apple")
	res1 := b.SearchKeys(*re1)
	if res1.Len() != 1 {
		t.Errorf("SearchKeys expected 1 match, got %d", res1.Len())
	}

	// Search by key or value
	re2 := regexp.MustCompile("(?i)red")
	res2 := b.SearchKeysAndValues(*re2)
	if res2.Len() != 2 {
		t.Errorf("SearchKeysAndValues expected 2 matches, got %d", res2.Len())
	}

	// No match
	re3 := regexp.MustCompile("Grape")
	res3 := b.SearchKeys(*re3)
	if res3.Len() != 0 {
		t.Errorf("SearchKeys expected 0 matches, got %d", res3.Len())
	}
}

func TestSecretListCombined(t *testing.T) {
	b1 := newSecretList([]secret{secret(`A
val`)})
	b2 := newSecretList([]secret{secret(`B
val`)})

	combined := b1.Combined(b2)
	if combined.Len() != 2 {
		t.Errorf("Combined expected 2 secrets, got %d", combined.Len())
	}

	if string(combined.secrets[0].Key()) != "A" || string(combined.secrets[1].Key()) != "B" {
		t.Errorf("Combined secrets out of order or incorrect")
	}
}

func TestSecretKey(t *testing.T) {
	s := secret(`My Key
My Value
More Value`)
	if string(s.Key()) != "My Key" {
		t.Errorf("Key() expected %q, got %q", "My Key", s.Key())
	}

	s2 := secret("SingleLineKey")
	if string(s2.Key()) != "SingleLineKey" {
		t.Errorf("Key() expected %q, got %q", "SingleLineKey", s2.Key())
	}
}

// The rules that make wiping mean anything: a secretList owns copies of what it
// was parsed from, wiping it clears them, and what it hands back is a copy that
// the wipe does not reach.
func TestASecretListOwnsAndWipesItsSecrets(t *testing.T) {
	plaintext := []byte("Key1\nValue1\n\nKey2\nValue2\n")
	b, err := parseSecrets(plaintext)
	if err != nil {
		t.Fatalf("parseSecrets failed: %v", err)
	}

	// Wiping what it was parsed from leaves the secretList intact, so a caller
	// can clear the vault's plaintext as soon as it has been read.
	crypto.Wipe(plaintext)
	if got := string(b.secrets[0]); got != "Key1\nValue1\n" {
		t.Errorf("expected the secretList to hold its own copy, got %q", got)
	}

	// What it hands back outlives the wipe, which is what lets Search return
	// matches and then clear everything it read.
	out := b.Bytes()
	if got := string(out); got != "Key1\nValue1\n\nKey2\nValue2\n" {
		t.Fatalf("Bytes() = %q", got)
	}
	held := b.secrets[0]
	b.Wipe()
	if string(out) != "Key1\nValue1\n\nKey2\nValue2\n" {
		t.Errorf("expected Bytes() to be a copy, got %q", out)
	}
	for _, c := range held {
		if c != 0 {
			t.Fatalf("expected every secret to be zeroed, got %q", held)
		}
	}
}
