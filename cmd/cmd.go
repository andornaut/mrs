package cmd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/andornaut/mrs/cmd/vaultcmd"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/secret"
	"github.com/andornaut/mrs/internal/vault"
	"github.com/spf13/cobra"
)

// Cmd implements the root ./mrs command
var Cmd = &cobra.Command{
	Use:          "mrs",
	Example:      "\tmrs vault create\n\tmrs edit\n\tmrs search 'secret stuff'",
	Short:        "Mr. Secretary",
	Long:         "Mr. Secretary - Organise and secure your secrets",
	SilenceUsage: true,
}

var (
	includeValues bool
	namePrefix    string
	passwordFile  string
)

var add = &cobra.Command{
	Use:   "add",
	Short: "Add secrets to a vault",
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
	Short: "Edit secrets in a vault",
	Long:  "Use an editor ($EDITOR) to edit your secrets",
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
	Short: "Search for secrets in a vault",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		// Internal whitespace is stripped by cobra, so we search for any amount of internal whitespace.
		// Users can surround a single argument with quotation marks for more precise control of internal whitespace.
		// Additionally, add a "case-insensitive" flag.
		rs := "(?i)" + strings.Join(args, "\\s+")
		r, err := regexp.Compile(rs)
		if err != nil {
			return fmt.Errorf("invalid regular expression \"%s\": %s", rs, err)
		}
		v, err := getUnlockedVault()
		if err != nil {
			return err
		}
		if v == vault.BadUnlockedVault {
			return errors.New("no vaults found")
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
		namePrefix = prompt.PromptName()
	}
	return vault.First(namePrefix)
}

// Get a Vault and then unlock it.
func getUnlockedVault() (vault.UnlockedVault, error) {
	v, err := getVault()
	if err != nil {
		return vault.BadUnlockedVault, err
	}
	p, err := prompt.GivenOrPromptPassword(passwordFile)
	if err != nil {
		return vault.BadUnlockedVault, err
	}
	return v.Unlocked(p), nil
}

func init() {
	for _, c := range []*cobra.Command{add, edit, search} {
		flags := c.Flags()
		flags.StringVarP(&namePrefix, "vault", "v", "", "name of a vault")
		flags.StringVarP(&passwordFile, "password-file", "p", "", "path to a file that contains your password")
	}
	search.Flags().BoolVarP(&includeValues, "full", "f", false, "search the full contents, instead of the first line of each secret")
	Cmd.AddCommand(add, edit, search, vaultcmd.Cmd)
}
