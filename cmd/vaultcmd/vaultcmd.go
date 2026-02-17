package vaultcmd

import (
	"errors"
	"fmt"

	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/vault"
	"github.com/spf13/cobra"
)

// Cmd implements ./mrs vault
var Cmd = &cobra.Command{
	Use:          "vault [command]",
	Short:        "Manage vaults",
	SilenceUsage: true,
}

type vaultOptions struct {
	importFile   string
	isPath       bool
	namePrefix   string
	passwordFile string
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
			v, err := vault.Create(name, password, opts.importFile)
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
			v, err := vault.First(name)
			if err != nil {
				return err
			}
			unlock, err := v.ExclusiveLock()
			if err != nil {
				return err
			}
			defer unlock()

			oldPassword, err := prompt.GivenOrPromptPassword(opts.passwordFile)
			if err != nil {
				return err
			}
			defer crypto.Wipe(oldPassword)

			newPassword, err := prompt.Password("New password")
			if err != nil {
				return err
			}
			confirmPassword, err := prompt.Password("Confirm password")
			if err != nil {
				crypto.Wipe(newPassword)
				return err
			}
			defer crypto.Wipe(confirmPassword)

			if !crypto.SecureCompare(newPassword, confirmPassword) {
				crypto.Wipe(newPassword)
				return errors.New("password mismatch")
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
			v, err := vault.First(name)
			if err != nil {
				return err
			}
			unlock, err := v.ExclusiveLock()
			if err != nil {
				return err
			}
			defer unlock()

			if !prompt.Bool(fmt.Sprintf("Delete vault %s?", name), false) {
				return errors.New("cancelled")
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
			v, err := vault.First(name)
			if err != nil {
				return err
			}
			unlock, err := v.SharedLock()
			if err != nil {
				return err
			}
			defer unlock()

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

			v, err := vault.First(sourceName)
			if err != nil {
				return err
			}
			unlock, err := v.ExclusiveLock()
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

	for _, c := range []*cobra.Command{changePassword, create, delete, export} {
		c.Flags().StringVarP(&opts.namePrefix, "vault", "v", "", "name of a vault")
	}
	for _, c := range []*cobra.Command{changePassword, create, export} {
		c.Flags().StringVarP(&opts.passwordFile, "password-file", "p", "", "path to a file that contains your password")
	}

	create.Flags().StringVarP(&opts.importFile, "import-file", "i", "", "path to a file that contains unencrypted secrets")
	getDefault.Flags().BoolVarP(&opts.isPath, "path", "p", false, "print the vault path instead of the name")
	list.Flags().BoolVarP(&opts.isPath, "path", "p", false, "print vault paths instead of names")

	Cmd.AddCommand(changePassword, create, delete, export, getDefault, list, rename)
}
