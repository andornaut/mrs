package vaultcmd

import (
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
	Args: cli.NeedsCommand,
	RunE: func(c *cobra.Command, args []string) error { return nil },
	// `mrs vault` takes no flags of its own beyond --help, so the usage line
	// reads as the two things it can be: the group, or a command within it.
	DisableFlagsInUseLine: true,
}

type vaultOptions struct {
	assumeYes       bool
	repairLock      bool
	importFile      string
	isPath          bool
	newPasswordFile string
	passwordFile    string
}

// locked resolves the vault named exactly by name and takes its exclusive
// lock. Every command here changes or removes a vault, so none of them accepts
// a prefix: a name that is short of the whole thing must not reach a
// neighbouring vault. The vault is resolved before the lock is taken and
// before anything is asked, so that a name that is not a vault is refused
// outright rather than after the user has answered a prompt about it.
func (o *vaultOptions) locked(name string) (vault.Vault, func(), error) {
	v, err := vault.Exact(name)
	if err != nil {
		return "", nil, err
	}
	unlock, err := v.ExclusiveLockRepair(o.repairLock)
	if err != nil {
		return "", nil, err
	}
	return v, unlock, nil
}

// runChangePassword re-keys a vault. What was given on the command line is
// checked before anything is asked for, as create checks its name and its
// import file.
func (o *vaultOptions) runChangePassword(name string) error {
	v, unlock, err := o.locked(name)
	if err != nil {
		return err
	}
	defer unlock()

	// A new password given as a file is read and checked before the current one
	// is asked for: a change that cannot succeed must not first make the user
	// type the password they already have. One that is typed cannot be checked
	// before it is typed, so that order is unchanged.
	var newPassword []byte
	if o.newPasswordFile != "" {
		newPassword, err = prompt.GivenOrPromptNewPassword(o.newPasswordFile)
		if err != nil {
			return err
		}
		defer crypto.Wipe(newPassword)
		// Advisory: vault.ChangePassword checks again, which is the answer that
		// counts.
		if validateErr := vault.ValidatePassword(newPassword); validateErr != nil {
			return fmt.Errorf("invalid new password: %w", validateErr)
		}
	}

	oldPassword, err := prompt.GivenOrPromptPassword(o.passwordFile)
	if err != nil {
		return err
	}
	defer crypto.Wipe(oldPassword)

	if newPassword == nil {
		newPassword, err = prompt.GivenOrPromptNewPassword(o.newPasswordFile)
		if err != nil {
			return err
		}
		defer crypto.Wipe(newPassword)
	}

	uv, err := vault.ChangePassword(v, oldPassword, newPassword)
	if err != nil {
		return err
	}
	defer uv.Wipe()
	fmt.Fprintf(os.Stderr, "Changed password of vault %s\n", uv)
	return nil
}

func init() {
	opts := &vaultOptions{}

	create := &cobra.Command{
		Use:                   "create <name>",
		Short:                 "Create a vault",
		Args:                  cli.RequireArgs(1, 1, "a name for the new vault"),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			// The name and the import file are checked before anything is
			// asked, so that a create that cannot succeed does not first make
			// the user type a password twice.
			if err := vault.ValidateName(name); err != nil {
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

			v, err := vault.Create(name, password, contents, opts.repairLock)
			if err != nil {
				return err
			}
			defer v.Wipe()
			fmt.Fprintf(os.Stderr, "Created vault %s\n", v)
			return nil
		},
	}

	changePassword := &cobra.Command{
		Use:                   "change-password <name>",
		Short:                 "Change a vault's password",
		Args:                  cli.RequireArgs(1, 1, "the name of a vault"),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return opts.runChangePassword(args[0])
		},
	}

	deleteCmd := &cobra.Command{
		Use:                   "delete <name>",
		Short:                 "Delete a vault",
		Args:                  cli.RequireArgs(1, 1, "the name of a vault"),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			v, unlock, err := opts.locked(args[0])
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
			fmt.Fprintf(os.Stderr, "Deleted vault %s\n", v.Name())
			return nil
		},
	}

	getDefault := &cobra.Command{
		Use:                   "default",
		Short:                 "Print the default vault",
		Long:                  "Print the vault that $MRS_DEFAULT_VAULT_NAME names, or the only vault there is",
		Args:                  cli.NoArgs,
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			v, err := vault.Default()
			if err != nil {
				return err
			}
			if opts.isPath {
				fmt.Println(v.Path())
			} else {
				fmt.Println(v.Name())
			}
			return nil
		},
	}

	list := &cobra.Command{
		Use:                   "list",
		Short:                 "List all vaults",
		Args:                  cli.NoArgs,
		DisableFlagsInUseLine: true,
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
		Use:                   "rename <source-name> <target-name>",
		Short:                 "Rename a vault",
		Args:                  cli.RequireArgs(2, 2, "a source name and a target name"),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			sourceName, targetName := args[0], args[1]
			v, unlock, err := opts.locked(sourceName)
			if err != nil {
				return err
			}
			defer unlock()

			if err := vault.Rename(v, targetName, opts.repairLock); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Renamed vault %s to %s\n", sourceName, targetName)
			return nil
		},
	}

	for _, c := range []*cobra.Command{changePassword, create} {
		c.Flags().StringVarP(&opts.passwordFile, "password-file", "p", "", "path to a file that contains your password")
	}
	// --force has no short form, because it is not the flag a hurried -f is
	// reaching for: it repairs a lock rather than overwriting anything, and is
	// worth spelling out.
	//
	// Every command that takes a lock takes it, and it means one thing on all
	// of them: make a lock file that cannot be used usable again. It never
	// takes a lock another process holds, so it is as safe on the name create
	// claims, and on the name rename claims, as it is on a vault being written.
	for _, c := range []*cobra.Command{changePassword, create, deleteCmd, rename} {
		c.Flags().BoolVar(&opts.repairLock, "force", false, "repair a lock file that cannot be used")
	}
	deleteCmd.Flags().BoolVarP(&opts.assumeYes, "yes", "y", false, "answer yes to the confirmation")

	changePassword.Flags().StringVarP(&opts.newPasswordFile, "new-password-file", "n", "", "path to a file that contains your new password")
	create.Flags().StringVarP(&opts.importFile, "import-file", "i", "", "path to a file that contains unencrypted secrets")
	// --path has no short form, so that -p means the password file on every
	// command that has one. These two never take a password, but -p meaning
	// two things under `mrs vault` is a trap for the person typing, not for
	// the parser.
	getDefault.Flags().BoolVar(&opts.isPath, "path", false, "print the vault path instead of the name")
	list.Flags().BoolVar(&opts.isPath, "path", false, "print vault paths instead of names")

	Cmd.AddCommand(changePassword, create, deleteCmd, getDefault, list, rename)
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
