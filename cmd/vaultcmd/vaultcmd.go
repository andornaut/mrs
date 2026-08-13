package vaultcmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/secret"
	"github.com/andornaut/mrs/internal/vault"
)

// Cmd implements ./mrs vault
var Cmd = &cobra.Command{
	Use:   "vault [command]",
	Short: "Manage vaults",
	// Without Args and RunE, an unrecognised subcommand prints help and exits 0,
	// which hides a typo such as `mrs vault lst` from a script. Args alone is
	// not enough: cobra returns help before validating the arguments of a
	// command that has no RunE.
	Args: cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		return c.Help()
	},
	SilenceUsage: true,
}

type vaultOptions struct {
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
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			name, err := prompt.GivenOrPromptName(opts.namePrefix)
			if err != nil {
				return err
			}
			password, err := prompt.GivenOrPromptConfirmedPassword(opts.passwordFile)
			if err != nil {
				return err
			}
			contents, err := readImportFile(opts.importFile)
			if err != nil {
				return err
			}
			defer crypto.Wipe(contents)

			v, err := vault.Create(name, password, contents, opts.force)
			if err != nil {
				return err
			}
			defer v.Wipe()
			fmt.Printf("Created vault %s\n", v)
			return nil
		},
	}

	changePassword := &cobra.Command{
		Use:   "change-password",
		Short: "Change a vault's password",
		Args:  cobra.NoArgs,
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

			uv, err := vault.ChangePassword(name, oldPassword, newPassword)
			if err != nil {
				return err
			}
			defer uv.Wipe()
			fmt.Printf("Changed password of vault %s\n", uv)
			return nil
		},
	}

	delete := &cobra.Command{
		Use:   "delete",
		Short: "Delete a vault",
		Args:  cobra.NoArgs,
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

			if !prompt.Bool(fmt.Sprintf("Delete vault %s?", v.Name()), false) {
				// Declining the confirmation is a normal outcome, not a failure.
				fmt.Println("Cancelled")
				return nil
			}
			if err := vault.Delete(name); err != nil {
				return err
			}
			fmt.Printf("Deleted vault %s\n", name)
			return nil
		},
	}

	export := &cobra.Command{
		Use:   "export",
		Short: "Export secrets from a vault",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			name, err := prompt.GivenOrPromptName(opts.namePrefix)
			if err != nil {
				return err
			}

			password, err := prompt.GivenOrPromptPassword(opts.passwordFile)
			if err != nil {
				return err
			}
			defer crypto.Wipe(password)

			s, err := vault.Export(name, password)
			if err != nil {
				return err
			}
			fmt.Print(s)
			return nil
		},
	}

	getDefault := &cobra.Command{
		Use:   "get-default",
		Short: "Print the default vault",
		Long:  "Print either the first vault or the one defined by $MRS_DEFAULT_VAULT_NAME",
		Args:  cobra.NoArgs,
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
		Args:  cobra.NoArgs,
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
		Use:                   "rename [source-name] [target-name]",
		Short:                 "Rename a vault",
		Args:                  cobra.ExactArgs(2),
		DisableFlagsInUseLine: true,
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

			if err := vault.Rename(sourceName, targetName); err != nil {
				return err
			}
			fmt.Printf("Renamed vault %s to %s\n", sourceName, targetName)
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
	for _, c := range []*cobra.Command{changePassword, create, delete, rename} {
		c.Flags().BoolVarP(&opts.force, "force", "f", false, "delete the vault's lock file first")
	}

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
		return nil, fmt.Errorf("could not read from import file at %s: %s", importFile, err)
	}
	if err := secret.Validate(b); err != nil {
		crypto.Wipe(b)
		return nil, fmt.Errorf("could not import %s: %s", importFile, err)
	}
	return b, nil
}
