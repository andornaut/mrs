package secret

import (
	"bytes"
	"fmt"
	"os"
	"regexp"

	"github.com/andornaut/mrs/internal/cli"
	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/vault"
)

// Add prompts the user to add secrets to a vault
func Add(v vault.UnlockedVault) (int, error) {
	b, err := readSecrets(v)
	if err != nil {
		return 0, err
	}
	defer b.Wipe()

	// Nothing to edit: an add session opens on an empty buffer.
	nb, err := editSecrets(nil)
	if err != nil {
		return 0, err
	}
	defer nb.Wipe()

	// Combined holds the same secrets as both, so wiping those two wipes it.
	if err := save(v, b.Combined(nb)); err != nil {
		return 0, err
	}
	return nb.Len(), nil
}

// Edit prompts the user to edit secrets in a vault. assumeYes accepts emptying
// it without asking. It reports whether the changes were saved, which is false
// when the user declines to empty the vault.
func Edit(assumeYes bool, v vault.UnlockedVault) (bool, error) {
	b, err := readSecrets(v)
	if err != nil {
		return false, err
	}
	defer b.Wipe()
	before := b.Len()

	current := b.Bytes()
	edited, err := editSecrets(current)
	crypto.Wipe(current)
	if err != nil {
		return false, err
	}
	defer edited.Wipe()

	// Emptying a vault discards every secret in it at once, so confirm it
	// rather than treating it as an ordinary edit.
	if before > 0 && edited.Len() == 0 {
		msg := fmt.Sprintf("This will remove all %d %s from vault %s. Continue?",
			before, cli.Plural(before, "secret"), v)
		confirmed, err := prompt.Confirm(assumeYes, msg)
		if err != nil {
			return false, err
		}
		if !confirmed {
			return false, nil
		}
	}

	if err := save(v, edited); err != nil {
		return false, err
	}
	return true, nil
}

// save warns about duplicate keys, as every save does, and writes the secrets
// back to the vault in the shape a vault is written in.
func save(v vault.UnlockedVault, b *secretList) error {
	warnDuplicateKeys(b)
	out := b.Bytes()
	defer crypto.Wipe(out)
	return v.Write(out)
}

// warnDuplicateKeys reports keys that more than one secret shares. mrs does not
// merge them, and a search returns each of them, so the user is told rather
// than left to discover it.
//
// The list is sorted, so secrets sharing a key sit within a run of fold-equal
// keys, and only those runs are examined. No key is copied out of its secret:
// a map keyed by string would leave an unwipeable copy of every key behind,
// while %q below prints straight from the secret's own memory, which is the
// exposure the warning itself has.
func warnDuplicateKeys(b *secretList) {
	for i := 0; i < len(b.secrets); {
		j := i + 1
		for j < len(b.secrets) && compareFold(b.secrets[i].Key(), b.secrets[j].Key()) == 0 {
			j++
		}
		warnDuplicateKeysInRun(b.secrets[i:j])
		i = j
	}
}

// warnDuplicateKeysInRun warns about the exactly-equal keys within one run of
// fold-equal keys. The sort is stable, so two exact duplicates need not sit
// beside each other when a key differing only in case arrived between them.
func warnDuplicateKeysInRun(run []secret) {
	if len(run) < 2 {
		return
	}
	counted := make([]bool, len(run))
	for a, s := range run {
		if counted[a] {
			continue
		}
		n := 1
		for c := a + 1; c < len(run); c++ {
			if !counted[c] && bytes.Equal(s.Key(), run[c].Key()) {
				counted[c] = true
				n++
			}
		}
		if n > 1 {
			fmt.Fprintf(os.Stderr, "Warning: %d secrets share the key %q\n", n, s.Key())
		}
	}
}

// Validate reports whether mrs can read the given secrets back. Every command
// that reads a vault parses its contents first, so contents that fail here
// would leave a vault that only export can read.
//
// It warns about duplicate keys as a save does, because it has parsed the
// secrets and so can. An import is where duplicates arrive, so it is the one
// moment the warning is most worth having, and a caller that only heard it on
// the next save would hear it about a file it no longer has.
func Validate(b []byte) error {
	parsed, err := parseSecrets(b)
	if err != nil {
		return err
	}
	defer parsed.Wipe()
	warnDuplicateKeys(parsed)
	return nil
}

// Search returns the secrets from a vault that match a regular expression, in
// the shape a vault is written in, along with how many matched. The caller is
// responsible for wiping the returned slice.
func Search(r *regexp.Regexp, includeValues bool, v vault.UnlockedVault) ([]byte, int, error) {
	b, err := readSecrets(v)
	if err != nil {
		return nil, 0, err
	}
	defer b.Wipe()

	matched := b.Search(r, includeValues)
	// Bytes copies, which has to happen before the deferred wipe: a match holds
	// the same memory as the secret it was found in.
	return matched.Bytes(), matched.Len(), nil
}
