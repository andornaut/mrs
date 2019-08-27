package secret

import (
	"regexp"

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
	if err := v.Write(b.String()); err != nil {
		return 0, err
	}
	return nb.Len(), nil
}

// Edit prompts the user to edit secrets in a vault
func Edit(v vault.UnlockedVault) error {
	b, err := retrieveBriefcase(v)
	if err != nil {
		return err
	}

	b, err = takeDictation(b.String())
	if err != nil {
		return err
	}

	return v.Write(b.String())
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
