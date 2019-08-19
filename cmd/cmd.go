package cmd

import (
	"errors"
	"io/ioutil"
	"log"

	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/vault"
	"github.com/spf13/cobra"
)

// Cmd implements the root ./mrs command
var Cmd = &cobra.Command{
	Use:          "mrs [command]",
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
	return prompt.TrimmedLine("Enter the vault name")
}

func flagOrPromptName() string {
	if namePrefix == "" {
		return promptName()
	}
	return namePrefix
}

func flagOrPromptPassword() string {
	if passwordFile == "" {
		return prompt.Password("Enter a password")
	}
	password, err := ioutil.ReadFile(passwordFile)
	if err != nil {
		log.Fatalf("Could not read from password file %s", passwordFile)
	}
	return string(password)
}

func getUnlockedVault() (vault.UnlockedVault, error) {
	n := flagOrPromptName()
	v, err := vault.Find(n)
	if err != nil {
		return vault.BadUnlockedVault, err
	}
	return v.Unlocked(flagOrPromptPassword()), nil
}

func getOrCreateUnlockedVault() (vault.UnlockedVault, error) {
	v, err := vault.Find(namePrefix)
	if err != nil {
		return vault.BadUnlockedVault, err
	}
	if v != vault.BadVault {
		return v.Unlocked(flagOrPromptPassword()), nil
	}
	if !prompt.Bool("You need to create a vault in order to continue. Create one now?", true) {
		return vault.BadUnlockedVault, errors.New("run `mrs create-vault` to create a vault")
	}
	return vault.Create(promptName(), flagOrPromptPassword(), "")
}

func init() {
	for _, c := range []*cobra.Command{add, createVault, deleteVault, edit, exportVault, search} {
		c.Flags().StringVarP(&namePrefix, "vault", "v", "", "name of vault")
	}
	for _, c := range []*cobra.Command{add, createVault, edit, exportVault, search} {
		c.Flags().StringVarP(&passwordFile, "password-file", "p", "", "path to a file that contains your password")
	}

	createVault.Flags().StringVarP(&importFile, "import-file", "i", "", "path to a file that contains unencrypted secrets")
	getDefaultVault.Flags().BoolVarP(&isPath, "path", "p", false, "print the path instead of the name")
	listVaults.Flags().BoolVarP(&isPath, "path", "p", false, "print paths instead of names")

	Cmd.AddCommand(add, createVault, deleteVault, edit, exportVault, getDefaultVault, listVaults, renameVault, search)
}
