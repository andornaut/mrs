package secret

import (
	"regexp"
	"strings"
	"testing"
)

func TestTranscribe(t *testing.T) {
	input := `
# This is a comment
Key1
Value1
More Value1

Key2
Value2

# Another comment
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
