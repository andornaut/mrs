package cmd

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/mrs/cmd/vaultcmd"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/secret"
	"github.com/andornaut/mrs/internal/vault"
)

// Cmd implements the root ./mrs command
var Cmd = &cobra.Command{
	Use:          "mrs",
	Example:      "\tmrs vault create\n\tmrs edit\n\tmrs search secret stuff",
	Short:        "Mr. Secretary",
	Long:         "Mr. Secretary - Organise and secure your secrets",
	SilenceUsage: true,
}

// noMatch records that a search ran and matched nothing. Finding nothing is
// not a failure and is not reported as one, so it is tracked here rather than
// returned as an error: an error would be printed as one, and silencing that
// would also silence the flag and argument errors cobra raises before a
// command ever runs.
var noMatch bool

// Execute runs mrs and returns the exit code the process should use.
func Execute() int {
	if err := Cmd.Execute(); err != nil {
		return 1
	}
	// Exit non-zero for a search that found nothing, as grep does, so that a
	// script can tell it from one that found something.
	if noMatch {
		return 1
	}
	return 0
}

// noArgs refuses positional arguments for add and edit. cobra.NoArgs reports
// them as an unknown command, which misdescribes `mrs add "my key"`: that is a
// user expecting to name a secret, and the answer is where secrets are typed.
func noArgs(c *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("%s takes no arguments, but got %q. Secrets are typed in your editor, not on the command line",
			c.CommandPath(), args[0])
	}
	return nil
}

// plural returns word, pluralised for n.
func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

type rootOptions struct {
	force         bool
	includeValues bool
	namePrefix    string
	passwordFile  string
}

func init() {
	opts := &rootOptions{}

	add := &cobra.Command{
		Use:   "add",
		Short: "Add secrets to a vault",
		Long:  "Use an editor ($EDITOR) to add secrets to a vault",
		Args:  noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			v, err := opts.getVault()
			if err != nil {
				return err
			}
			unlock, err := v.ExclusiveLockForce(opts.force)
			if err != nil {
				return err
			}
			defer unlock()

			password, err := prompt.GivenOrPromptPassword(opts.passwordFile)
			if err != nil {
				return err
			}
			uv := v.Unlocked(password)
			defer uv.Wipe()

			n, err := secret.Add(uv)
			if err != nil {
				return err
			}
			if n == 0 {
				fmt.Printf("No secrets added to vault %s\n", uv.Name())
			} else {
				fmt.Printf("%d %s added to vault %s\n", n, plural(n, "secret"), uv)
			}
			return nil
		},
	}

	edit := &cobra.Command{
		Use:   "edit",
		Short: "Edit secrets in a vault",
		Long:  "Use an editor ($EDITOR) to edit the secrets in a vault",
		Args:  noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			v, err := opts.getVault()
			if err != nil {
				return err
			}
			unlock, err := v.ExclusiveLockForce(opts.force)
			if err != nil {
				return err
			}
			defer unlock()

			password, err := prompt.GivenOrPromptPassword(opts.passwordFile)
			if err != nil {
				return err
			}
			uv := v.Unlocked(password)
			defer uv.Wipe()

			saved, err := secret.Edit(uv)
			if err != nil {
				return err
			}
			if !saved {
				fmt.Println("Cancelled")
				return nil
			}
			fmt.Printf("Saved changes to vault %s\n", uv)
			return nil
		},
	}

	search := &cobra.Command{
		Use:   "search <regular expression>...",
		Short: "Search for secrets in a vault",
		Long: "Search a vault for secrets whose key matches a regular expression.\n" +
			"Several arguments are joined, so \"mrs search aws key\" matches \"aws key\"\n" +
			"with any amount of whitespace between the words.",
		Args: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("nothing to search for. Give a regular expression, as in \"%s aws\"", c.CommandPath())
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			return opts.runSearch(args)
		},
	}

	for _, c := range []*cobra.Command{add, edit, search} {
		flags := c.Flags()
		flags.StringVarP(&opts.namePrefix, "vault", "v", "", "name of a vault, or the start of one")
		flags.StringVarP(&opts.passwordFile, "password-file", "p", "", "path to a file that contains your password")
	}
	add.Flags().BoolVarP(&opts.force, "force", "f", false, "delete the vault's lock file first")
	edit.Flags().BoolVarP(&opts.force, "force", "f", false, "delete the vault's lock file first")
	// -a, not -f: search takes no lock, so --force means nothing to it, and -f
	// is --force on every command that does take one.
	search.Flags().BoolVarP(&opts.includeValues, "full", "a", false, "search the full contents, instead of the first line of each secret")
	// Registered here so that cobra does not add it with a "-v" shorthand of
	// its own, which would make -v mean --version on `mrs` and --vault on
	// every command under it.
	Cmd.Flags().Bool("version", false, "version for mrs")
	Cmd.AddCommand(add, edit, search, vaultcmd.Cmd)
}

// runSearch compiles the query, reads the vault, and reports what matched.
func (o *rootOptions) runSearch(args []string) error {
	// Internal whitespace is stripped by cobra, so we search for any amount of internal whitespace.
	// Users can surround a single argument with quotation marks for more precise control of internal whitespace.
	// Additionally, add a "case-insensitive" flag.
	rs := "(?i)" + strings.Join(args, "\\s+")
	// What the user typed, for reporting back. The pattern above adds a
	// case-insensitivity flag and joins the arguments, so echoing it would show
	// them a search they did not write.
	query := strings.Join(args, " ")
	r, err := regexp.Compile(rs)
	if err != nil {
		return fmt.Errorf("invalid regular expression %q: %w", query, err)
	}
	v, err := o.getVault()
	if err != nil {
		return err
	}

	password, err := prompt.GivenOrPromptPassword(o.passwordFile)
	if err != nil {
		return err
	}
	uv := v.Unlocked(password)
	defer uv.Wipe()

	secrets, err := secret.Search(uv, *r, o.includeValues)
	if err != nil {
		return err
	}
	// The report goes to stderr and the secrets to stdout, so that
	// `mrs search aws > keys` and `mrs search aws | less` carry the secrets
	// alone, as `vault export` already does.
	n := len(secrets)
	if n == 0 {
		fmt.Fprintf(os.Stderr, "No secrets matched %q in vault %s\n", query, uv)
		noMatch = true
		return nil
	}
	fmt.Fprintf(os.Stderr, "%d %s matched %q in vault %s\n\n", n, plural(n, "secret"), query, uv)
	fmt.Print(strings.Join(secrets, "\n"))
	return nil
}

func (o *rootOptions) getVault() (vault.Vault, error) {
	if o.namePrefix == "" {
		v, err := vault.Default()
		if err != nil {
			return v, err
		}
		if v == vault.BadVault {
			// Default() returns BadVault without an error only when there are
			// no vaults at all, so asking which one to use has no answer.
			return vault.BadVault, errors.New("no vaults found. Run \"mrs vault create\" to create one")
		}
		return v, nil
	}
	return vault.First(o.namePrefix)
}
