package cmd

import (
	"fmt"

	"github.com/andornaut/mrs/internal/vault"
	"github.com/spf13/cobra"
)

var createVault = &cobra.Command{
	Use:   "create-vault",
	Short: "Create a vault",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := flagOrPromptName()
		password := flagOrPromptPassword()
		v, err := vault.Create(name, password, importFile)
		if err != nil {
			return err
		}
		fmt.Printf("Created vault %s\n", v)
		return nil
	},
}

var deleteVault = &cobra.Command{
	Use:   "delete-vault",
	Short: "Delete a vault",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := flagOrPromptName()
		if err := vault.Delete(name); err != nil {
			return err
		}
		fmt.Printf("Deleted vault %s\n", name)
		return nil
	},
}

var exportVault = &cobra.Command{
	Use:   "export-vault",
	Short: "Export secrets from a vault",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		name := flagOrPromptName()
		password := flagOrPromptPassword()
		s, err := vault.Export(name, password)
		if err != nil {
			return err
		}
		fmt.Print(s)
		return nil
	},
}

var getDefaultVault = &cobra.Command{
	Use:   "get-default-vault",
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

var listVaults = &cobra.Command{
	Use:   "list-vaults",
	Short: "Print all vaults",
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