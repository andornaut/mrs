package cmd

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/mrs/cmd/vaultcmd"
	"github.com/andornaut/mrs/internal/cli"
	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/secret"
	"github.com/andornaut/mrs/internal/vault"
)

// Cmd implements the root ./mrs command
var Cmd = &cobra.Command{
	Use:     "mrs",
	Example: "  mrs vault create personal\n  mrs edit\n  mrs search secret stuff",
	Short:   "Mr. Secretary",
	Long:    "Mr. Secretary - Organise and secure your secrets",
	// Cobra reports an unknown command from its own argument validator, which
	// this replaces so that the failure is marked as a wrong invocation and
	// exits 2. Without a RunE the root would never validate its arguments at
	// all: it would print help and report success for a mistyped command.
	Args: cli.NeedsCommand,
	// Never reached, since the arguments never validate, but a command cobra
	// does not consider runnable has its arguments ignored altogether.
	RunE: func(c *cobra.Command, args []string) error { return nil },
	// Runs once the arguments have been accepted and before any command does
	// its work, which is where a failure stops being a wrong invocation worth
	// printing usage for.
	PersistentPreRunE: func(c *cobra.Command, args []string) error {
		c.SilenceUsage = true
		return nil
	},
}

// errNoMatch reports that a search ran and matched nothing. Finding nothing is
// not a failure, so the command that returns it silences cobra's own reporting
// first; ExitCode turns it into a status of its own.
var errNoMatch = errors.New("no secrets matched")

// Exit codes. 2 is kept for a wrong invocation so that a script can tell a
// command it typed wrong from one that ran and failed, and 3 for a search that
// matched nothing, which is neither. A run cut short by a signal exits
// 128+signum, which cannot collide with any of these.
const (
	exitFailed  = 1
	exitUsage   = 2
	exitNoMatch = 3
)

// ExitCode returns the status that mrs should exit with for the given error,
// and 0 for no error.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, errNoMatch) {
		return exitNoMatch
	}
	if _, ok := errors.AsType[cli.UsageError](err); ok {
		return exitUsage
	}
	return exitFailed
}

// noEditorArgs refuses positional arguments for add and edit. cli.NoArgs says
// only that the command takes none, which is true but unhelpful for
// `mrs add "my key"`: that is a user expecting to name a secret, and the answer
// is where secrets are typed.
func noEditorArgs(c *cobra.Command, args []string) error {
	if len(args) > 0 {
		return cli.Usagef("%s takes no arguments, but got %q. Secrets are typed in your editor, not on the command line",
			c.CommandPath(), args[0])
	}
	return nil
}

type rootOptions struct {
	assumeYes     bool
	repairLock    bool
	includeValues bool
	namePrefix    string
	passwordFile  string
}

// unlocked resolves the vault, takes its exclusive lock and unlocks it with the
// user's password, then hands it to fn. The order is the point: the lock is
// taken before the password is asked for, so that a user does not type one for
// a vault another process is already writing.
func (o *rootOptions) unlocked(fn func(vault.UnlockedVault) error) error {
	v, err := vault.Named(o.namePrefix)
	if err != nil {
		return err
	}
	unlock, err := v.ExclusiveLockRepair(o.repairLock)
	if err != nil {
		return err
	}
	defer unlock()

	password, err := prompt.GivenOrPromptPassword(o.passwordFile)
	if err != nil {
		return err
	}
	uv := v.Unlocked(password)
	defer uv.Wipe()
	return fn(uv)
}

func init() {
	opts := &rootOptions{}

	add := &cobra.Command{
		Use:   "add",
		Short: "Add secrets to a vault",
		Long: "Use an editor ($VISUAL or $EDITOR) to add secrets to a vault.\n" +
			"Secrets are separated by blank lines. The first line of each secret\n" +
			"is its key; the rest is its value.",
		Args:                  noEditorArgs,
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return opts.unlocked(func(uv vault.UnlockedVault) error {
				n, err := secret.Add(uv)
				if err != nil {
					return err
				}
				if n == 0 {
					fmt.Fprintf(os.Stderr, "No secrets added to vault %s\n", uv.Name())
				} else {
					fmt.Fprintf(os.Stderr, "%d %s added to vault %s\n", n, cli.Plural(n, "secret"), uv)
				}
				return nil
			})
		},
	}

	edit := &cobra.Command{
		Use:   "edit",
		Short: "Edit secrets in a vault",
		Long: "Use an editor ($VISUAL or $EDITOR) to edit the secrets in a vault.\n" +
			"Secrets are separated by blank lines. The first line of each secret\n" +
			"is its key; the rest is its value.",
		Args:                  noEditorArgs,
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return opts.unlocked(func(uv vault.UnlockedVault) error {
				saved, err := secret.Edit(opts.assumeYes, uv)
				if err != nil {
					return err
				}
				if !saved {
					fmt.Fprintln(os.Stderr, "Cancelled")
					return nil
				}
				fmt.Fprintf(os.Stderr, "Saved changes to vault %s\n", uv)
				return nil
			})
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
				return cli.Usagef("%s requires a regular expression, as in \"%s aws\"", c.CommandPath(), c.CommandPath())
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			return opts.runSearch(c, args)
		},
	}

	export := &cobra.Command{
		Use:                   "export",
		Short:                 "Print every secret in a vault",
		Long:                  "Print a vault's secrets to stdout, in the shape a vault is written in",
		Args:                  cli.NoArgs,
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			// Reading, so it takes a prefix and falls back to the default
			// vault, as search does. The two differ only in what they print.
			v, err := vault.Named(opts.namePrefix)
			if err != nil {
				return err
			}
			password, err := prompt.GivenOrPromptPassword(opts.passwordFile)
			if err != nil {
				return err
			}
			defer crypto.Wipe(password)

			secrets, err := vault.Export(v, password)
			if err != nil {
				return err
			}
			defer crypto.Wipe(secrets)
			_, err = os.Stdout.Write(secrets)
			return err
		},
	}

	// Every command here reads or writes secrets in a vault it does not create,
	// destroy or move, so each takes the same two flags with the same meaning.
	// The vault may be named by a prefix, which has to fit exactly one vault.
	for _, c := range []*cobra.Command{add, edit, search, export} {
		c.Flags().StringVarP(&opts.namePrefix, "vault", "v", "", "name of a vault, or the start of one")
		c.Flags().StringVarP(&opts.passwordFile, "password-file", "p", "", "path to a file that contains your password")
		// The only error this returns is a flag that was not registered, which
		// the line above just registered.
		_ = c.RegisterFlagCompletionFunc("vault", cli.CompleteVaultNames)
	}
	// --force has no short form, because it is not the flag a hurried -f is
	// reaching for: it repairs a lock rather than overwriting anything, and is
	// worth spelling out.
	for _, c := range []*cobra.Command{add, edit} {
		c.Flags().BoolVar(&opts.repairLock, "force", false, "repair a lock file that cannot be used")
	}
	edit.Flags().BoolVarP(&opts.assumeYes, "yes", "y", false, "answer yes to the confirmation before emptying the vault")
	search.Flags().BoolVarP(&opts.includeValues, "full", "f", false, "search the full contents, instead of the first line of each secret")
	// Registered here so that cobra does not add it with a "-v" shorthand of
	// its own, which would make -v mean --version on `mrs` and --vault on
	// every command under it.
	Cmd.Flags().Bool("version", false, "version for mrs")
	// A flag cobra could not parse is a wrong invocation, and exits 2 like one.
	Cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error { return cli.Usage(err) })
	// The generated completion command is noise in the listing of a program
	// with this few commands, and still works when it is not listed.
	Cmd.CompletionOptions.HiddenDefaultCmd = true
	Cmd.AddCommand(add, edit, export, search, vaultcmd.Cmd)
}

// runSearch compiles the query, reads the vault, and reports what matched.
func (o *rootOptions) runSearch(c *cobra.Command, args []string) error {
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
	v, err := vault.Named(o.namePrefix)
	if err != nil {
		return err
	}

	password, err := prompt.GivenOrPromptPassword(o.passwordFile)
	if err != nil {
		return err
	}
	uv := v.Unlocked(password)
	defer uv.Wipe()

	secrets, n, err := secret.Search(uv, *r, o.includeValues)
	if err != nil {
		return err
	}
	defer crypto.Wipe(secrets)
	// The report goes to stderr and the secrets to stdout, so that
	// `mrs search aws > keys` and `mrs search aws | less` carry the secrets
	// alone, as `mrs export` already does.
	if n == 0 {
		fmt.Fprintf(os.Stderr, "No secrets matched %q in vault %s\n", query, uv)
		// Matching nothing is a result, not a failure, so the error that
		// carries the exit status is not printed as one.
		c.SilenceErrors = true
		return errNoMatch
	}
	fmt.Fprintf(os.Stderr, "%d %s matched %q in vault %s\n\n", n, cli.Plural(n, "secret"), query, uv)
	_, err = os.Stdout.Write(secrets)
	return err
}
