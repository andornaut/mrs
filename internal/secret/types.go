package secret

import (
	"regexp"
	"sort"
	"strings"
)

type secret string

func (s secret) Key() string {
	return strings.SplitN(string(s), "\n", 2)[0]
}

func (s secret) Less(o secret) bool {
	return strings.ToLower(s.Key()) < strings.ToLower(o.Key())
}

func (s secret) MatchKey(r regexp.Regexp) bool {
	return r.MatchString(s.Key())
}

func (s secret) MatchKeyAndValue(r regexp.Regexp) bool {
	return r.MatchString(s.String())
}

func (s secret) String() string {
	return string(s)
}

// briefcase holds secrets
type briefcase struct {
	secrets []secret
}

func newBriefcase(secrets []secret) *briefcase {
	s := &briefcase{secrets}
	sort.Sort(s)
	return s
}

// Combined returns a new Secrets object with the given secrets appended
func (s *briefcase) Combined(o *briefcase) *briefcase {
	merged := append(s.secrets, o.secrets...)
	return newBriefcase(merged)
}

// SearchKeys returns secrets whose keys match the given regular expression
func (s *briefcase) SearchKeys(r regexp.Regexp) *briefcase {
	return s.search(r, func(s secret, r regexp.Regexp) bool {
		return s.MatchKey(r)
	})
}

// SearchKeysAndValues returns secrets whose keys or value match the given regular expression
func (s *briefcase) SearchKeysAndValues(r regexp.Regexp) *briefcase {
	return s.search(r, func(s secret, r regexp.Regexp) bool {
		return s.MatchKeyAndValue(r)
	})
}

func (s *briefcase) search(r regexp.Regexp, match func(secret, regexp.Regexp) bool) *briefcase {
	var secrets []secret
	for _, secret := range s.secrets {
		if match(secret, r) {
			secrets = append(secrets, secret)
		}
	}
	return newBriefcase(secrets)
}

func (s *briefcase) String() string {
	return strings.Join(s.StringSlice(), "\n")
}

// StringSlice returns its secrets as a slice of strings
func (s *briefcase) StringSlice() []string {
	var entries []string
	for _, secret := range s.secrets {
		entries = append(entries, secret.String())
	}
	return entries
}

// Len is part of sort.Interface.
func (s *briefcase) Len() int {
	return len(s.secrets)
}

// Less is part of sort.Interface. It is implemented by calling the "by" closure in the sorter
func (s *briefcase) Less(i, j int) bool {
	return s.secrets[i].Less(s.secrets[j])
}

// Swap is part of sort.Interface
func (s *briefcase) Swap(i, j int) {
	s.secrets[i], s.secrets[j] = s.secrets[j], s.secrets[i]
}
