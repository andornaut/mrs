package cmd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/andornaut/mrs/internal/secret"
	"github.com/andornaut/mrs/internal/vault"
	"github.com/spf13/cobra"
)

var add = &cobra.Command{
	Use:   "add",
	Short: "Add secrets",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		v, err := getUnlockedVault()
		if err != nil {
			return err
		}
		n, err := secret.Add(v)
		if err != nil {
			return err
		}
		if n == 0 {
			fmt.Printf("No secrets added to vault %s\n", v.Name())
		} else {
			fmt.Printf("%d secret(s) added to vault %s\n", n, v)
		}
		return nil
	},
}

var edit = &cobra.Command{
	Use:   "edit",
	Short: "Edit secrets",
	Long:  "Use the editor defined by $EDITOR to edit decrypted vaults",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		v, err := getUnlockedVault()
		if err != nil {
			return err
		}
		if err := secret.Edit(v); err != nil {
			return err
		}
		fmt.Printf("Saved changes to vault %s\n", v)
		return nil
	},
}

var search = &cobra.Command{
	Use:   "search [regular expression]",
	Short: "Search through your secrets",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		// Internal whitespace is stripped by cobra, so search for any amount of internal whitespace.
		// Users can surround a single argument with quotation marks for more precise control of internal whitespace.
		rs := strings.Join(args, "\\s+")
		r, err := regexp.Compile(rs)
		if err != nil {
			return fmt.Errorf("invalid regular expression \"%s\": %s", rs, err)
		}
		v, err := getUnlockedVault()
		if err != nil {
			return err
		}
		if v == vault.BadUnlockedVault {
			return errors.New("No vaults found")
		}
		secrets, err := secret.Search(v, *r, includeValues)
		if err != nil {
			return err
		}
		n := len(secrets)
		if n == 0 {
			fmt.Printf("No secrets matched regular expression \"%s\" in vault %s\n", r, v)
		} else {
			fmt.Printf("%d secret(s) matched regular expression \"%s\" in vault %s\n\n%s", n, r, v, strings.Join(secrets, "\n"))
		}
		return nil
	},
}

func getVault() (vault.Vault, error) {
	if namePrefix == "" {
		v, err := vault.Default()
		if err != nil {
			return v, err
		}
		if v != vault.BadVault {
			return v, nil
		}
		namePrefix = promptName()
	}
	return vault.Find(namePrefix)
}

// Get a Vault and then unlock it.
func getUnlockedVault() (vault.UnlockedVault, error) {
	v, err := getVault()
	if err != nil {
		return vault.BadUnlockedVault, err
	}
	p, err := flagOrPromptPassword()
	if err != nil {
		return vault.BadUnlockedVault, err
	}
	return v.Unlocked(p), nil
}
