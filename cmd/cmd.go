package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/andornaut/mrs/internal/prompt"
	"github.com/spf13/cobra"
)

// Cmd implements the root ./mrs command
var Cmd = &cobra.Command{
	Use:          "mrs",
	Example:      "\tmrs create-vault --vault name\n\tmrs edit\n\tmrs search 'secret stuff'",
	Short:        "Mr. Secretary",
	Long:         "Mr. Secretary - Organise and secure your secrets",
	SilenceUsage: true,
}

var (
	importFile    string
	includeValues bool
	isPath        bool
	passwordFile  string
	namePrefix    string
)

func promptName() string {
	return prompt.TrimmedLine("Vault name")
}

func flagOrPromptName() string {
	if namePrefix == "" {
		return promptName()
	}
	return namePrefix
}

func readPasswordFile() (string, error) {
	password, err := ioutil.ReadFile(passwordFile)
	if err != nil {
		return "", fmt.Errorf("Could not read from password file %s: %s", passwordFile, err)
	}
	return string(password), nil
}

func flagOrPromptPassword() (string, error) {
	if passwordFile != "" {
		return readPasswordFile()
	}
	return prompt.Password("Vault password"), nil
}

func flagOrPromptConfirmedPassword() (string, error) {
	if passwordFile != "" {
		return readPasswordFile()
	}
	p := prompt.Password("Vault password")
	c := prompt.Password("Confirm password")
	if p != c {
		return "", errors.New("Passord mismatch")
	}
	return p, nil
}

func init() {
	for _, c := range []*cobra.Command{add, changeVaultPassword, createVault, deleteVault, edit, exportVault, search} {
		c.Flags().StringVarP(&namePrefix, "vault", "v", "", "name of vault")
	}
	for _, c := range []*cobra.Command{add, changeVaultPassword, createVault, edit, exportVault, search} {
		c.Flags().StringVarP(&passwordFile, "password-file", "p", "", "path to a file that contains your password")
	}

	createVault.Flags().StringVarP(&importFile, "import-file", "i", "", "path to a file that contains unencrypted secrets")
	getDefaultVault.Flags().BoolVarP(&isPath, "path", "p", false, "print the path instead of the name")
	listVaults.Flags().BoolVarP(&isPath, "path", "p", false, "print paths instead of names")

	Cmd.AddCommand(add, changeVaultPassword, createVault, deleteVault, edit, exportVault, getDefaultVault, listVaults, renameVault, search)
}
