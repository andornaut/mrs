package vaultcmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/andornaut/mrs/internal/cli"
	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/secret"
	"github.com/andornaut/mrs/internal/vault"
)

// Cmd implements ./mrs vault
var Cmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage vaults",
	// Without Args and RunE, an unrecognised subcommand prints help and exits 0,
	// which hides a typo such as `mrs vault lst` from a script.
	RunE: func(c *cobra.Command, args []string) error {
		if len(args) > 0 {
			return cli.Usagef("unknown command %q for %q. Run \"%s --help\" for usage", args[0], c.CommandPath(), c.CommandPath())
		}
		return c.Help()
	},
	// `mrs vault` takes no flags of its own beyond --help, so the usage line
	// reads as the two things it can be: the group, or a command within it.
	DisableFlagsInUseLine: true,
	SilenceUsage:          true,
}

// noArgs refuses positional arguments. cobra.NoArgs reports them as an unknown
// command, which is right for `mrs vault lst` but not for a command that has no
// subcommands: `mrs vault export personal` names a vault, not a command.
func noArgs(c *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	msg := fmt.Sprintf("%s takes no arguments, but got %q", c.CommandPath(), args[0])
	// A vault is named by a flag, so an argument is most often a name in the
	// wrong place. list and get-default take no vault, so they say nothing.
	if c.Flags().Lookup("vault") != nil {
		msg += ". Use --vault to name a vault"
	}
	return cli.Usage(errors.New(msg))
}

type vaultOptions struct {
	assumeYes       bool
	force           bool
	importFile      string
	isPath          bool
	namePrefix      string
	newPasswordFile string
	passwordFile    string
}

func init() {
	opts := &vaultOptions{}

	create := &cobra.Command{
		Use:   "create",
		Short: "Create a vault",
		Args:  noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			name, err := prompt.GivenOrPromptName(opts.namePrefix)
			if err != nil {
				return err
			}
			// The name and the import file are checked before anything is
			// asked, as delete resolves its vault before asking, so that a
			// create that cannot succeed does not first make the user type a
			// password twice.
			if err = vault.ValidateName(name); err != nil {
				return err
			}
			// Advisory: vault.Create checks again under the lock, which is the
			// answer that counts. This one only spares the user from typing a
			// password for a vault that is already there.
			taken, err := vault.Exists(name)
			if err != nil {
				return err
			}
			if taken {
				return fmt.Errorf("a vault named %q already exists", name)
			}
			contents, err := readImportFile(opts.importFile)
			if err != nil {
				return err
			}
			defer crypto.Wipe(contents)

			password, err := prompt.GivenOrPromptConfirmedPassword(opts.passwordFile)
			if err != nil {
				return err
			}

			v, err := vault.Create(name, password, contents, opts.force)
			if err != nil {
				return err
			}
			defer v.Wipe()
			fmt.Fprintf(os.Stderr, "Created vault %s\n", v)
			return nil
		},
	}

	changePassword := &cobra.Command{
		Use:   "change-password",
		Short: "Change a vault's password",
		Args:  noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			name, err := prompt.GivenOrPromptName(opts.namePrefix)
			if err != nil {
				return err
			}
			// Re-keying a vault changes it, so it takes the whole name.
			v, err := vault.Exact(name)
			if err != nil {
				return err
			}
			unlock, err := v.ExclusiveLockForce(opts.force)
			if err != nil {
				return err
			}
			defer unlock()

			oldPassword, err := prompt.GivenOrPromptPassword(opts.passwordFile)
			if err != nil {
				return err
			}
			defer crypto.Wipe(oldPassword)

			newPassword, err := prompt.GivenOrPromptNewPassword(opts.newPasswordFile)
			if err != nil {
				return err
			}
			defer crypto.Wipe(newPassword)

			uv, err := vault.ChangePassword(v, oldPassword, newPassword)
			if err != nil {
				return err
			}
			defer uv.Wipe()
			fmt.Fprintf(os.Stderr, "Changed password of vault %s\n", uv)
			return nil
		},
	}

	delete := &cobra.Command{
		Use:   "delete",
		Short: "Delete a vault",
		Args:  noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			name, err := prompt.GivenOrPromptName(opts.namePrefix)
			if err != nil {
				return err
			}
			// Resolved before the lock is taken and before anything is asked,
			// so that a name that is not a vault is refused outright rather
			// than after the user has confirmed deleting it. Deleting requires
			// the whole name: a prefix must not reach a neighbouring vault.
			v, err := vault.Exact(name)
			if err != nil {
				return err
			}
			unlock, err := v.ExclusiveLockForce(opts.force)
			if err != nil {
				return err
			}
			defer unlock()

			confirmed, err := prompt.Confirm(opts.assumeYes, fmt.Sprintf("Delete vault %s?", v.Name()))
			if err != nil {
				return err
			}
			if !confirmed {
				// Declining the confirmation is a normal outcome, not a failure.
				fmt.Fprintln(os.Stderr, "Cancelled")
				return nil
			}
			if err := vault.Delete(v); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Deleted vault %s\n", name)
			return nil
		},
	}

	export := &cobra.Command{
		Use:   "export",
		Short: "Export secrets from a vault",
		Args:  noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			// Reading, so it takes a prefix and falls back to the default vault,
			// as search does. The two differ only in what they print.
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

	getDefault := &cobra.Command{
		Use: "default",
		// The former name, kept so that it goes on working where it is
		// already written down.
		Aliases: []string{"get-default"},
		Short:   "Print the default vault",
		Long:    "Print the vault that $MRS_DEFAULT_VAULT_NAME names, or the only vault there is",
		Args:    noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			v, err := vault.Default()
			if err != nil {
				return err
			}
			if v != vault.BadVault {
				if opts.isPath {
					fmt.Println(v.Path())
				} else {
					fmt.Println(v.Name())
				}
			}
			return nil
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List all vaults",
		Args:  noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			vaults, err := vault.All()
			if err != nil {
				return err
			}
			for _, v := range vaults {
				if opts.isPath {
					fmt.Println(v.Path())
				} else {
					fmt.Println(v.Name())
				}
			}
			return nil
		},
	}

	rename := &cobra.Command{
		Use:   "rename <source-name> <target-name>",
		Short: "Rename a vault",
		Args: func(c *cobra.Command, args []string) error {
			if len(args) != 2 {
				return cli.Usagef("%s requires a source name and a target name", c.CommandPath())
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			sourceName := args[0]
			targetName := args[1]

			// Resolved exactly, and before the lock, for the same reason as
			// delete: a rename moves a vault, so a prefix must not reach one
			// the user did not name.
			v, err := vault.Exact(sourceName)
			if err != nil {
				return err
			}
			unlock, err := v.ExclusiveLockForce(opts.force)
			if err != nil {
				return err
			}
			defer unlock()

			if err := vault.Rename(v, targetName); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Renamed vault %s to %s\n", sourceName, targetName)
			return nil
		},
	}

	// Reading a vault takes a name prefix; changing one takes the whole name,
	// so that a prefix cannot reach a vault the user did not name. The help
	// text says which, because the flag alone cannot.
	create.Flags().StringVarP(&opts.namePrefix, "vault", "v", "", "name for the new vault")
	export.Flags().StringVarP(&opts.namePrefix, "vault", "v", "", "name of a vault, or the start of one")
	for _, c := range []*cobra.Command{changePassword, delete} {
		c.Flags().StringVarP(&opts.namePrefix, "vault", "v", "", "full name of a vault")
	}
	for _, c := range []*cobra.Command{changePassword, create, export} {
		c.Flags().StringVarP(&opts.passwordFile, "password-file", "p", "", "path to a file that contains your password")
	}
	// --force has no short form, because it is not the flag a hurried -f is
	// reaching for: it breaks another process's lock rather than overwriting
	// anything, and is worth spelling out.
	for _, c := range []*cobra.Command{changePassword, create, delete, rename} {
		c.Flags().BoolVar(&opts.force, "force", false, "delete the vault's lock file first")
	}
	delete.Flags().BoolVarP(&opts.assumeYes, "yes", "y", false, "answer yes to the confirmation")

	changePassword.Flags().StringVarP(&opts.newPasswordFile, "new-password-file", "n", "", "path to a file that contains your new password")
	create.Flags().StringVarP(&opts.importFile, "import-file", "i", "", "path to a file that contains unencrypted secrets")
	// --path has no short form, so that -p means the password file on every
	// command that has one. These two never take a password, but -p meaning
	// two things under `mrs vault` is a trap for the person typing, not for
	// the parser.
	getDefault.Flags().BoolVar(&opts.isPath, "path", false, "print the vault path instead of the name")
	list.Flags().BoolVar(&opts.isPath, "path", false, "print vault paths instead of names")

	Cmd.AddCommand(changePassword, create, delete, export, getDefault, list, rename)
}

// readImportFile returns the secrets to seed a new vault with, and refuses a
// file that mrs could not read back. Contents are stored as they are written,
// but a vault whose contents cannot be parsed is one that only export can
// read: add, edit and search each parse the secrets first and would fail on it
// for good. The caller is responsible for wiping the returned slice.
func readImportFile(importFile string) ([]byte, error) {
	if importFile == "" {
		return nil, nil
	}
	b, err := os.ReadFile(importFile)
	if err != nil {
		return nil, fmt.Errorf("could not read from import file %q: %w", importFile, err)
	}
	if err := secret.Validate(b); err != nil {
		crypto.Wipe(b)
		return nil, fmt.Errorf("could not import %q: %w", importFile, err)
	}
	return b, nil
}
