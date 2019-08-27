# Mr. Secretary (mrs) - Organise and secure your secrets

`mrs` is a secrets manager for Linux and OS/X.

## Features

- Organise your secrets into one or more encrypted "vaults"
- Edit your secrets via the editor of your choice
- Search through your secrets using regular expressions
- Import and export your secrets
- Encrypt your secrets with [256-bit AES-GCM](https://tools.ietf.org/html/rfc5288)

## Usage

```
Mr. Secretary - Organise and secure your secrets

Usage:
  mrs [command]

Examples:
	mrs create-vault --vault name
	mrs edit
	mrs search 'secret stuff'

Available Commands:
  add             Add secrets to a vault
  change-password Change a vault password
  create-vault    Create a vault
  delete-vault    Delete a vault
  edit            Edit secrets
  export          Export secrets from a vault
  get-default     Print the default vault
  help            Help about any command
  list            List all vaults
  rename-vault    Rename a vault
  search          Search through your secrets

Flags:
  -h, --help   help for mrs

Use "mrs [command] --help" for more information about a command.
```

## Configuration

You can use environment variables to customize some settings.

Environment variable | Description
---|---
EDITOR | The editor to use to add or edit secrets (default: nano)
MRS_DEFAULT_VAULT_NAME | The vault to use when `--vault` is not specified (default: the first vault found)
MRS_HIDE_EDITOR_INSTRUCTIONS | If set to any value, then instructions comments will not be included when adding or editing secrets
MRS_HOME | The directory where `mrs` stores encrypted vault files (default: `${HOME}/.local/share/mrs`)
MRS_TEMP | The directory where `mrs` stores temporary decrypted files (default `$XDG_RUNTIME_DIR`)

## Developing

See the [Makefile](./Makefile).
