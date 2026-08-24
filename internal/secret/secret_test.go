package secret

import (
	"bytes"
	"regexp"
	"slices"
	"testing"

	"github.com/andornaut/mrs/internal/crypto"
)

func TestEveryLineIsPartOfASecretIncludingOneThatBeginsWithAHash(t *testing.T) {
	// Every line is a line of secrets, including one that begins with a "#".
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

func TestParseSecretsPreservesWhitespaceWithinSecrets(t *testing.T) {
	input := "Key1\n  indented\ntrailing   \n\nKey2\nValue2\n"
	b, err := parseSecrets([]byte(input))
	if err != nil {
		t.Fatalf("parseSecrets failed: %v", err)
	}
	if got, expected := string(b.secrets[0]), "Key1\n  indented\ntrailing   \n"; got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestASearchLooksAtKeysAndAtValuesOnlyWithFull(t *testing.T) {
	// "red" appears in two values and in no key, so it tells the two searches
	// apart: without it, a SearchKeys that also matched values would pass.
	b := newSecretList([]secret{
		secret("Apple\ncolor: red"),
		secret("Banana\ncolor: yellow"),
		secret("Cherry\ncolor: red"),
	})

	tests := []struct {
		name    string
		search  func(*secretList, regexp.Regexp) *secretList
		pattern string
		want    []string
	}{
		{"a key", (*secretList).SearchKeys, "(?i)apple", []string{"Apple"}},
		{"a value is not a key", (*secretList).SearchKeys, "(?i)red", nil},
		{"no match at all", (*secretList).SearchKeys, "Grape", nil},
		{"a value, with --full", (*secretList).SearchKeysAndValues, "(?i)red", []string{"Apple", "Cherry"}},
		{"a key, with --full", (*secretList).SearchKeysAndValues, "(?i)banana", []string{"Banana"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.search(b, *regexp.MustCompile(tt.pattern))
			keys := make([]string, 0, got.Len())
			for _, s := range got.secrets {
				keys = append(keys, string(s.Key()))
			}
			if !slices.Equal(keys, tt.want) {
				t.Errorf("matched %v, want %v", keys, tt.want)
			}
		})
	}
}

// Secrets are ordered by key ignoring case, so "apple" sorts before "Zebra"
// rather than after every capital letter, which comparing bytes would give.
// Keys that differ only in length are ordered by it, so a key that is another's
// prefix comes first.
func TestSecretsAreSortedIgnoringCase(t *testing.T) {
	b := newSecretList([]secret{
		secret("Zebra\nvalue"),
		secret("apple\nvalue"),
		secret("Banana\nvalue"),
		secret("app\nvalue"),
	})

	want := []string{"app", "apple", "Banana", "Zebra"}
	got := make([]string, 0, b.Len())
	for _, s := range b.secrets {
		got = append(got, string(s.Key()))
	}
	if !slices.Equal(got, want) {
		t.Errorf("sorted %v, want %v", got, want)
	}
}

func TestCombiningTwoListsKeepsBothInKeyOrder(t *testing.T) {
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

func TestTheKeyIsTheFirstLineOfASecret(t *testing.T) {
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

// A trailing carriage return is the tail of a CRLF, so every one of them goes.
// A line is re-read after a save with the newline written back on the end of
// it, so stripping one at a time would shed another from a value ending in one
// on every save, silently, until none was left.
func TestEveryTrailingCarriageReturnIsStripped(t *testing.T) {
	for desc, tt := range map[string]struct{ in, want string }{
		"a CRLF line ending":       {"key\r\nvalue\r\n", "key\nvalue\n"},
		"a lone trailing return":   {"key\nvalue\r", "key\nvalue\n"},
		"several trailing returns": {"key\nvalue\r\r\r\n", "key\nvalue\n"},
		"one within a line":        {"key\nbefore\rafter\n", "key\nbefore\rafter\n"},
	} {
		t.Run(desc, func(t *testing.T) {
			b, err := parseSecrets([]byte(tt.in))
			if err != nil {
				t.Fatalf("parseSecrets() error: %v", err)
			}
			if got := string(b.Bytes()); got != tt.want {
				t.Errorf("parseSecrets(%q) wrote back %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// What a vault holds is what parseSecrets made of the file the editor saved,
// written back out by Bytes and parsed again the next time the vault is opened.
// A first parse may normalise, but the second has to be a fixed point, or a
// vault would drift every time it was saved.
func FuzzParseSecretsRoundTripsWhatItAccepts(f *testing.F) {
	for _, seed := range []string{
		"",
		"key\nvalue\n",
		"key",
		"\n\n\n",
		"a\n\n\n\nb\n",
		"key\r\nvalue\r\n",
		"  \t \nkey\nvalue\n",
		"key\nvalue\n\nkey\nanother\n",
		"Zebra\nv\n\napple\nv\n",
		"app\nv\n\nApp\nv\n\nAPP\nv\n",
		"key\n\x00binary\n",
		"#not a comment\nvalue\n",
		"  indented\ntrailing   \n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		first, err := parseSecrets(in)
		if err != nil {
			// The only refusal is a line past the limit, which needs an input
			// at least that long.
			if len(in) > maxLineLen {
				t.Skip()
			}
			t.Fatalf("parseSecrets(%q) = %v", in, err)
		}
		out := first.Bytes()

		second, err := parseSecrets(out)
		if err != nil {
			t.Fatalf("parseSecrets() refused what Bytes() wrote for %q: %v", in, err)
		}
		if again := second.Bytes(); !bytes.Equal(out, again) {
			t.Fatalf("parsing is not a fixed point for %q:\n first  %q\n second %q", in, out, again)
		}

		// The shape that makes the round trip hold: a secret ends in a newline,
		// so that the blank line Bytes writes between two of them is a
		// separator, and holds no blank line of its own for the next parse to
		// split it on.
		for _, s := range first.secrets {
			if len(s) == 0 {
				t.Fatalf("parseSecrets(%q) kept an empty secret", in)
			}
			if s[len(s)-1] != '\n' {
				t.Fatalf("parseSecrets(%q) kept a secret not ending in a newline: %q", in, s)
			}
			for line := range bytes.SplitSeq(s[:len(s)-1], []byte{'\n'}) {
				if len(bytes.TrimSpace(line)) == 0 {
					t.Fatalf("parseSecrets(%q) kept a blank line inside %q", in, s)
				}
			}
		}
	})
}
