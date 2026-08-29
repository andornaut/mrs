// Package cli holds what the command packages share.
package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/mrs/internal/vault"
)

// AddPasswordFileFlag registers -p/--password-file. One registration shared by
// every command that takes a password, so that -p spells the same flag on all
// of them.
func AddPasswordFileFlag(c *cobra.Command, target *string) {
	c.Flags().StringVarP(target, "password-file", "p", "", "path to a file that contains your password")
}

// AddForceFlag registers --force. It has no short form, because it is not the
// flag a hurried -f is reaching for: it repairs a lock rather than overwriting
// anything, and is worth spelling out.
func AddForceFlag(c *cobra.Command, target *bool) {
	c.Flags().BoolVar(target, "force", false, "repair a lock file that cannot be used")
}

// AddYesFlag registers -y/--yes, answering the confirmation what names. One
// registration shared by every command that confirms, so that -y spells the
// same flag on all of them.
func AddYesFlag(c *cobra.Command, target *bool, what string) {
	c.Flags().BoolVarP(target, "yes", "y", false, "answer yes to "+what)
}

// UsageError marks a wrong invocation: an unknown command, an unknown flag, or
// an argument a command does not take. mrs exits 2 for these and 1 for a
// command that ran and failed, so that a script can tell them apart.
type UsageError struct{ err error }

func (e UsageError) Error() string { return e.err.Error() }

func (e UsageError) Unwrap() error { return e.err }

// Usage marks an existing error as a wrong invocation.
func Usage(err error) error { return UsageError{err} }

// Usagef reports a wrong invocation, as an argument validator does.
func Usagef(format string, a ...any) error { return UsageError{fmt.Errorf(format, a...)} }

// NeedsCommand refuses a command group invoked with no command, and an argument
// that names none. Both are wrong invocations: naming a command is how anything
// happens, and --help is how help is asked for. It validates arguments rather
// than running, so that the failure comes before usage is silenced and the
// reader is shown the commands they could have named.
func NeedsCommand(c *cobra.Command, args []string) error {
	if len(args) > 0 {
		return Usagef("unknown command %q for %q", args[0], c.CommandPath())
	}
	return Usagef("%s requires a command", c.CommandPath())
}

// NoArgs refuses operands. cobra.NoArgs reports them as an unknown command,
// which misdescribes a command that takes no operands at all rather than one
// that was misspelled.
func NoArgs(c *cobra.Command, args []string) error {
	if len(args) > 0 {
		return Usagef("%s takes no arguments, but got %q", c.CommandPath(), args[0])
	}
	return nil
}

// RequireArgs validates an operand count, naming the command and what it
// wanted. Cobra's own message ("accepts 1 arg(s), received 0") names neither.
func RequireArgs(n int, want string) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error {
		if len(args) < n {
			return Usagef("%s requires %s", c.CommandPath(), want)
		}
		if len(args) > n {
			// Say how many arrived, as NoArgs does. Too many operands is
			// usually a name the shell split on a space, and a message that
			// only restates what the command wanted does not show that.
			return Usagef("%s requires %s, but got %d arguments: %s",
				c.CommandPath(), want, len(args), strings.Join(quoted(args), " "))
		}
		return nil
	}
}

// quoted returns the arguments, each quoted, so that the one carrying a space
// can be told from two that do not.
func quoted(args []string) []string {
	qs := make([]string, 0, len(args))
	for _, a := range args {
		qs = append(qs, strconv.Quote(a))
	}
	return qs
}

// Plural returns word, pluralised for n.
func Plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// CompleteVaultNames offers the names of the vaults that exist, for an operand
// or a flag that names one. A shell asks for completions on every Tab, so a
// failure offers nothing rather than putting an error on the command line.
// Filenames are never offered alongside: a vault is named, not pathed.
func CompleteVaultNames(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	vs, err := vault.AllQuiet()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	names := make([]string, 0, len(vs))
	for _, v := range vs {
		if strings.HasPrefix(v.Name(), toComplete) {
			names = append(names, v.Name())
		}
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

// CompleteFirstVaultName offers vault names for the first operand only, for a
// command whose later operands name no vault, as rename's target is a name that
// no vault has yet.
func CompleteFirstVaultName(c *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return CompleteVaultNames(c, args, toComplete)
}
