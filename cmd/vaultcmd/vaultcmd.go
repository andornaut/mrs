package vaultcmd

import (
	"errors"
	"fmt"

	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/vault"
	"github.com/spf13/cobra"
)

var (
	importFile   string
	isPath       bool
	namePrefix   string
	passwordFile string
)

// Cmd implements ./mrs vault
var Cmd = &cobra.Command{
	Use:          "vault [command]",
	Short:        "Manage vaults",
	SilenceUsage: true,
}

var create = &cobra.Command{
	Use:   "create",
	Short: "Create a vault",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := prompt.GivenOrPromptName(namePrefix)
		password, err := prompt.GivenOrPromptConfirmedPassword(passwordFile)
		if err != nil {
			return err
		}
		v, err := vault.Create(name, password, importFile)
		if err != nil {
			return err
		}
		fmt.Printf("Created vault %s\n", v)
		return nil
	},
}

var changePassword = &cobra.Command{
	Use:   "change-password",
	Short: "Change a vault's password",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := prompt.GivenOrPromptName(namePrefix)
		oldPassword, err := prompt.GivenOrPromptPassword(passwordFile)
		if err != nil {
			return err
		}
		newPassword := prompt.Password("New password")
		confirmPassword := prompt.Password("Confirm password")
		if newPassword != confirmPassword {
			return errors.New("password mismatch")
		}
		v, err := vault.ChangePassword(name, oldPassword, newPassword)
		if err != nil {
			return err
		}
		fmt.Printf("Changed password of vault %s\n", v)
		return nil
	},
}

var delete = &cobra.Command{
	Use:   "delete",
	Short: "Delete a vault",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := prompt.GivenOrPromptName(namePrefix)
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

var export = &cobra.Command{
	Use:   "export",
	Short: "Export secrets from a vault",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := prompt.GivenOrPromptName(namePrefix)
		password, err := prompt.GivenOrPromptPassword(passwordFile)
		if err != nil {
			return err
		}
		s, err := vault.Export(name, password)
		if err != nil {
			return err
		}
		fmt.Print(s)
		return nil
	},
}

var getDefault = &cobra.Command{
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
			if isPath {
				fmt.Println(v.Path())
			} else {
				fmt.Println(v.Name())
			}
		}
		return nil
	},
}

var list = &cobra.Command{
	Use:   "list",
	Short: "List all vaults",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		vaults, err := vault.All()
		if err != nil {
			return err
		}
		for _, v := range vaults {
			if isPath {
				fmt.Println(v.Path())
			} else {
				fmt.Println(v.Name())
			}
		}
		return nil
	},
}

var rename = &cobra.Command{
	Use:                   "rename [source-name] [target-name]",
	Short:                 "Rename a vault",
	Args:                  cobra.ExactArgs(2),
	DisableFlagsInUseLine: true,
	RunE: func(c *cobra.Command, args []string) error {
		sourceName := args[0]
		targetName := args[1]
		if err := vault.Rename(sourceName, targetName); err != nil {
			return err
		}
		fmt.Printf("Renamed vault %s to %s\n", sourceName, targetName)
		return nil
	},
}

func init() {
	for _, c := range []*cobra.Command{changePassword, create, delete, export} {
		c.Flags().StringVarP(&namePrefix, "vault", "v", "", "name of a vault")
	}
	for _, c := range []*cobra.Command{changePassword, create, export} {
		c.Flags().StringVarP(&passwordFile, "password-file", "p", "", "path to a file that contains your password")
	}

	create.Flags().StringVarP(&importFile, "import-file", "i", "", "path to a file that contains unencrypted secrets")
	getDefault.Flags().BoolVarP(&isPath, "path", "p", false, "print the vault path instead of the name")
	list.Flags().BoolVarP(&isPath, "path", "p", false, "print vault paths instead of names")

	Cmd.AddCommand(changePassword, create, delete, export, getDefault, list, rename)
}
