package secret

import (
	"regexp"
	"strings"
	"testing"
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
	r := strings.NewReader(input)
	b, err := transcribe(r)
	if err != nil {
		t.Fatalf("transcribe failed: %v", err)
	}

	if b.Len() != 3 {
		t.Errorf("expected 3 secrets, got %d", b.Len())
	}

	expectedKeys := []string{"Key1", "Key2", "Key3"}
	for i, key := range expectedKeys {
		if b.secrets[i].Key() != key {
			t.Errorf("expected key %d to be %q, got %q", i, key, b.secrets[i].Key())
		}
	}
	if got := b.secrets[1].String(); got != "Key2\n#Value2\n" {
		t.Errorf("expected a value beginning with # to be kept, got %q", got)
	}
}

func TestTranscribePreservesWhitespaceWithinSecrets(t *testing.T) {
	input := "Key1\n  indented\ntrailing   \n\nKey2\nValue2\n"
	b, err := transcribe(strings.NewReader(input))
	if err != nil {
		t.Fatalf("transcribe failed: %v", err)
	}
	if got, expected := b.secrets[0].String(), "Key1\n  indented\ntrailing   \n"; got != expected {
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

func TestBriefcaseSearch(t *testing.T) {
	secrets := []secret{
		secret(`Apple
color: red`),
		secret(`Banana
color: yellow`),
		secret(`Cherry
color: red`),
	}
	b := newBriefcase(secrets)

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

func TestBriefcaseCombined(t *testing.T) {
	b1 := newBriefcase([]secret{secret(`A
val`)})
	b2 := newBriefcase([]secret{secret(`B
val`)})

	combined := b1.Combined(b2)
	if combined.Len() != 2 {
		t.Errorf("Combined expected 2 secrets, got %d", combined.Len())
	}

	if combined.secrets[0].Key() != "A" || combined.secrets[1].Key() != "B" {
		t.Errorf("Combined secrets out of order or incorrect")
	}
}

func TestSecretKey(t *testing.T) {
	s := secret(`My Key
My Value
More Value`)
	if s.Key() != "My Key" {
		t.Errorf("Key() expected %q, got %q", "My Key", s.Key())
	}

	s2 := secret("SingleLineKey")
	if s2.Key() != "SingleLineKey" {
		t.Errorf("Key() expected %q, got %q", "SingleLineKey", s2.Key())
	}
}
