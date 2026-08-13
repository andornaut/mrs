package secret

import (
	"fmt"
	"os"
	"regexp"

	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/vault"
)

// Add prompts the user to add secrets to a vault
func Add(v vault.UnlockedVault) (int, error) {
	b, err := retrieveBriefcase(v)
	if err != nil {
		return 0, err
	}

	nb, err := takeDictation("\n")
	if err != nil {
		return 0, err
	}

	b = b.Combined(nb)
	warnDuplicateKeys(b)
	if err := v.Write(b.String()); err != nil {
		return 0, err
	}
	return nb.Len(), nil
}

// Edit prompts the user to edit secrets in a vault.
// It reports whether the changes were saved, which is false when the user
// declines to empty the vault.
func Edit(v vault.UnlockedVault) (bool, error) {
	b, err := retrieveBriefcase(v)
	if err != nil {
		return false, err
	}
	before := b.Len()

	b, err = takeDictation(b.String())
	if err != nil {
		return false, err
	}

	// Emptying a vault discards every secret in it at once, so confirm it
	// rather than treating it as an ordinary edit.
	if before > 0 && b.Len() == 0 {
		msg := fmt.Sprintf("This will remove all %d secret(s) from vault %s. Continue?", before, v.Name())
		if !prompt.Bool(msg, false) {
			return false, nil
		}
	}

	warnDuplicateKeys(b)
	if err := v.Write(b.String()); err != nil {
		return false, err
	}
	return true, nil
}

// warnDuplicateKeys reports keys that more than one secret shares. mrs does not
// merge them, and a search returns each of them, so the user is told rather
// than left to discover it.
func warnDuplicateKeys(b *briefcase) {
	counts := make(map[string]int, b.Len())
	var duplicated []string
	for _, s := range b.secrets {
		k := s.Key()
		counts[k]++
		if counts[k] == 2 {
			duplicated = append(duplicated, k)
		}
	}
	for _, k := range duplicated {
		fmt.Fprintf(os.Stderr, "Warning: %d secrets share the key \"%s\"\n", counts[k], k)
	}
}

// Search returns secrets from a vault that match a regular expression
func Search(v vault.UnlockedVault, r regexp.Regexp, includeValues bool) ([]string, error) {
	b, err := retrieveBriefcase(v)
	if err != nil {
		return nil, err
	}
	if includeValues {
		b = b.SearchKeysAndValues(r)
	} else {
		b = b.SearchKeys(r)
	}
	return b.StringSlice(), nil
}
