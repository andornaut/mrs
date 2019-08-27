package cmd

import (
	"errors"
	"fmt"

	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/vault"
	"github.com/spf13/cobra"
)

var createVault = &cobra.Command{
	Use:   "create-vault",
	Short: "Create a vault",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := flagOrPromptName()
		password, err := flagOrPromptConfirmedPassword()
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
	Short: "Change a vault password",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := flagOrPromptName()
		oldPassword, err := flagOrPromptPassword()
		if err != nil {
			return err
		}
		newPassword := prompt.Password("New password")
		confirmPassword := prompt.Password("Confirm password")
		if newPassword != confirmPassword {
			return errors.New("Password mismatch")
		}
		v, err := vault.ChangePassword(name, oldPassword, newPassword)
		if err != nil {
			return err
		}
		fmt.Printf("Changed password of vault %s\n", v)
		return nil
	},
}

var deleteVault = &cobra.Command{
	Use:   "delete-vault",
	Short: "Delete a vault",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := flagOrPromptName()
		if !prompt.Bool(fmt.Sprintf("Delete vault %s?", name), false) {
			return errors.New("Cancelled")
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
		name := flagOrPromptName()
		password, err := flagOrPromptPassword()
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

var renameVault = &cobra.Command{
	Use:                   "rename-vault [source-name] [target-name]",
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
