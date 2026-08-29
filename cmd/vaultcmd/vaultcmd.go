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
	defer func() { crypto.Wipe(newPassword) }()
	// vault.ChangePassword checks the new password again, which is the answer
	// that counts.
	if o.newPasswordFile != "" {
		if newPassword, err = prompt.GivenOrPromptNewPassword(vault.ValidateNewPassword, o.newPasswordFile); err != nil {
			return err
		}
	}

	oldPassword, err := prompt.GivenOrPromptPassword(o.passwordFile)
	if err != nil {
		return err
	}
	defer crypto.Wipe(oldPassword)

	if newPassword == nil {
		if newPassword, err = prompt.GivenOrPromptNewPassword(vault.ValidateNewPassword, o.newPasswordFile); err != nil {
			return err
		}
	}

	uv, err := vault.ChangePassword(oldPassword, newPassword, v)
	if err != nil {
		return err
	}
	defer uv.Wipe()
	fmt.Fprintf(os.Stderr, "Changed password of vault %s\n", uv)
	return nil
}

// display returns what these commands print for a vault: its path when --path
// was given, and its name otherwise.
func (o *vaultOptions) display(v vault.Vault) string {
	if o.isPath {
		return v.Path()
	}
	return v.Name()
}

// printLine writes one line of the output a caller consumes, and reports a
// write it could not make. fmt.Println discards that error, so a listing sent
// to a full disk would be lost while the command reported success, which is
// what export and search already refuse to do.
func printLine(s string) error {
	_, err := fmt.Fprintln(os.Stdout, s)
	return err
}

func init() {
	opts := &vaultOptions{}

	create := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a vault",
		Args:  cli.RequireArgs(1, "a name for the new vault"),
		// A vault that does not exist yet has no name to offer, and is not a
		// file either.
		ValidArgsFunction:     cobra.NoFileCompletions,
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			// The import file is checked before anything is asked, so that a
			// create that cannot succeed does not first make the user type a
			// password twice. vault.Create checks the name, claims it under
			// the name's lock, and only then asks for the password.
			contents, err := readImportFile(opts.importFile)
			if err != nil {
				return err
			}
			defer crypto.Wipe(contents)

			v, err := vault.Create(contents, opts.repairLock, name, func() ([]byte, error) {
				return prompt.GivenOrPromptConfirmedPassword(vault.ValidatePassword, opts.passwordFile)
			})
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
		Args:                  cli.RequireArgs(1, "the name of a vault"),
		ValidArgsFunction:     cli.CompleteVaultNames,
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return opts.runChangePassword(args[0])
		},
	}

	deleteCmd := &cobra.Command{
		Use:                   "rm <name>",
		Short:                 "Delete a vault",
		Args:                  cli.RequireArgs(1, "the name of a vault"),
		ValidArgsFunction:     cli.CompleteVaultNames,
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
			return printLine(opts.display(v))
		},
	}

	list := &cobra.Command{
		Use:                   "ls",
		Short:                 "List all vaults",
		Args:                  cli.NoArgs,
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			vaults, err := vault.All()
			if err != nil {
				return err
			}
			for _, v := range vaults {
				if err := printLine(opts.display(v)); err != nil {
					return err
				}
			}
			return nil
		},
	}

	rename := &cobra.Command{
		Use:   "rename <source-name> <target-name>",
		Short: "Rename a vault",
		Args:  cli.RequireArgs(2, "a source name and a target name"),
		// The source names a vault; the target is a name no vault has yet.
		ValidArgsFunction:     cli.CompleteFirstVaultName,
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			sourceName, targetName := args[0], args[1]
			v, unlock, err := opts.locked(sourceName)
			if err != nil {
				return err
			}
			defer unlock()

			if err := vault.Rename(targetName, opts.repairLock, v); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Renamed vault %s to %s\n", sourceName, targetName)
			return nil
		},
	}

	for _, c := range []*cobra.Command{changePassword, create} {
		cli.AddPasswordFileFlag(c, &opts.passwordFile)
	}
	// Every command that takes a lock takes --force, and it means one thing on
	// all of them: make a lock file that cannot be used usable again. It never
	// takes a lock another process holds, so it is as safe on the name create
	// claims, and on the name rename claims, as it is on a vault being written.
	for _, c := range []*cobra.Command{changePassword, create, deleteCmd, rename} {
		cli.AddForceFlag(c, &opts.repairLock)
	}
	cli.AddYesFlag(deleteCmd, &opts.assumeYes, "the confirmation")

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
