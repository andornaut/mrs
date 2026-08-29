package secret

import (
	"bytes"
	"cmp"
	"regexp"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/andornaut/mrs/internal/crypto"
)

// secret is one secret's plaintext. It is bytes rather than a string so that it
// can be wiped: a string is immutable, so a secret held as one stays in memory
// until the collector runs, and every copy made along the way stays with it.
type secret []byte

// Key returns the secret's first line, which is what a search matches on. It
// shares the secret's memory, so wiping the secret wipes the key with it.
func (s secret) Key() []byte {
	if before, _, ok := bytes.Cut(s, []byte{'\n'}); ok {
		return before
	}
	return s
}

// compareFold orders a before b ignoring case. It folds as it reads, rather
// than lowercasing both first, which would leave an unwipeable copy of two
// keys behind for every comparison a sort makes.
func compareFold(a, b []byte) int {
	for len(a) > 0 && len(b) > 0 {
		ra, na := utf8.DecodeRune(a)
		rb, nb := utf8.DecodeRune(b)
		la, lb := unicode.ToLower(ra), unicode.ToLower(rb)
		if la != lb {
			return cmp.Compare(la, lb)
		}
		a, b = a[na:], b[nb:]
	}
	return cmp.Compare(len(a), len(b))
}

// secretList is the secrets of one vault, sorted by key.
type secretList struct {
	secrets []secret
}

func newSecretList(secrets []secret) *secretList {
	// Stable, so that secrets sharing a key keep the order they were typed in
	// rather than being shuffled by each save.
	slices.SortStableFunc(secrets, func(a, b secret) int {
		return compareFold(a.Key(), b.Key())
	})
	return &secretList{secrets}
}

// Wipe zeroes every secret in the secretList. A secretList built by a search
// holds the same secrets as the one it was searched from, so wiping either
// wipes both.
func (s *secretList) Wipe() {
	for _, secret := range s.secrets {
		crypto.Wipe(secret)
	}
}

// Combined returns a new secretList holding both lists' secrets, re-sorted
// by key
func (s *secretList) Combined(o *secretList) *secretList {
	return newSecretList(slices.Concat(s.secrets, o.secrets))
}

// Search returns the secrets whose keys match the given regular expression,
// or, when includeValues is true, the ones whose whole contents do. The result
// aliases the receiver's secrets, and is not re-sorted: a subsequence of a
// sorted list is sorted.
func (s *secretList) Search(r *regexp.Regexp, includeValues bool) *secretList {
	var secrets []secret
	for _, sec := range s.secrets {
		target := []byte(sec)
		if !includeValues {
			target = sec.Key()
		}
		if r.Match(target) {
			secrets = append(secrets, sec)
		}
	}
	return &secretList{secrets}
}

// Bytes returns the secrets as a vault is written: each ends in a newline, and
// a blank line separates one from the next. It is a copy, sized once so that
// growing it cannot leave a half-filled buffer behind, and the caller is
// responsible for wiping it.
func (s *secretList) Bytes() []byte {
	if len(s.secrets) == 0 {
		return nil
	}
	n := len(s.secrets) - 1
	for _, secret := range s.secrets {
		n += len(secret)
	}
	out := make([]byte, 0, n)
	for i, secret := range s.secrets {
		if i > 0 {
			out = append(out, '\n')
		}
		out = append(out, secret...)
	}
	return out
}

// Len returns the number of secrets.
func (s *secretList) Len() int {
	return len(s.secrets)
}
