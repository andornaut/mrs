package secret

import (
	"fmt"
	"os"
	"regexp"

	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/vault"
)

// Plural returns word, pluralised for n.
func Plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// Add prompts the user to add secrets to a vault
func Add(v vault.UnlockedVault) (int, error) {
	b, err := retrieveBriefcase(v)
	if err != nil {
		return 0, err
	}
	defer b.Wipe()

	nb, err := takeDictation([]byte("\n"))
	if err != nil {
		return 0, err
	}
	defer nb.Wipe()

	// Combined holds the same secrets as both, so wiping those two wipes it.
	combined := b.Combined(nb)
	warnDuplicateKeys(combined)
	out := combined.Bytes()
	defer crypto.Wipe(out)
	if err := v.Write(out); err != nil {
		return 0, err
	}
	return nb.Len(), nil
}

// Edit prompts the user to edit secrets in a vault. assumeYes accepts emptying
// it without asking. It reports whether the changes were saved, which is false
// when the user declines to empty the vault.
func Edit(assumeYes bool, v vault.UnlockedVault) (bool, error) {
	b, err := retrieveBriefcase(v)
	if err != nil {
		return false, err
	}
	defer b.Wipe()
	before := b.Len()

	current := b.Bytes()
	edited, err := takeDictation(current)
	crypto.Wipe(current)
	if err != nil {
		return false, err
	}
	defer edited.Wipe()

	// Emptying a vault discards every secret in it at once, so confirm it
	// rather than treating it as an ordinary edit.
	if before > 0 && edited.Len() == 0 {
		msg := fmt.Sprintf("This will remove all %d %s from vault %s. Continue?",
			before, Plural(before, "secret"), v.Name())
		confirmed, err := prompt.Confirm(assumeYes, msg)
		if err != nil {
			return false, err
		}
		if !confirmed {
			return false, nil
		}
	}

	warnDuplicateKeys(edited)
	out := edited.Bytes()
	defer crypto.Wipe(out)
	if err := v.Write(out); err != nil {
		return false, err
	}
	return true, nil
}

// warnDuplicateKeys reports keys that more than one secret shares. mrs does not
// merge them, and a search returns each of them, so the user is told rather
// than left to discover it.
func warnDuplicateKeys(b *briefcase) {
	// The keys counted here are the keys printed below, so holding one as a
	// string adds no exposure that the warning itself does not.
	counts := make(map[string]int, b.Len())
	var duplicated []string
	for _, s := range b.secrets {
		k := string(s.Key())
		counts[k]++
		if counts[k] == 2 {
			duplicated = append(duplicated, k)
		}
	}
	for _, k := range duplicated {
		fmt.Fprintf(os.Stderr, "Warning: %d secrets share the key %q\n", counts[k], k)
	}
}

// Validate reports whether mrs can read the given secrets back. Every command
// that reads a vault parses its contents first, so contents that fail here
// would leave a vault that only export can read.
func Validate(b []byte) error {
	parsed, err := transcribe(b)
	if err != nil {
		return err
	}
	parsed.Wipe()
	return nil
}

// Search returns the secrets from a vault that match a regular expression, in
// the shape a vault is written in, along with how many matched. The caller is
// responsible for wiping the returned slice.
func Search(v vault.UnlockedVault, r regexp.Regexp, includeValues bool) ([]byte, int, error) {
	b, err := retrieveBriefcase(v)
	if err != nil {
		return nil, 0, err
	}
	defer b.Wipe()

	matched := b.SearchKeys(r)
	if includeValues {
		matched = b.SearchKeysAndValues(r)
	}
	// Bytes copies, which has to happen before the deferred wipe: a match holds
	// the same memory as the secret it was found in.
	return matched.Bytes(), matched.Len(), nil
}
