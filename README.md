# Mr. Secretary (mrs) - Organise and secure your secrets

`mrs` is a secrets manager for Linux and OS/X.

## Features

- Organise your secrets into one or more encrypted "vaults"
- Edit your secrets via the editor of your choice
- Search through your secrets using regular expressions
- Import and export your secrets

## Usage

```
Mr. Secretary - Organise and secure your secrets

Usage:
  mrs [command]

Available Commands:
  add               Add secrets
  create-vault      Create a vault
  delete-vault      Delete a vault
  edit              Edit secrets
  export-vault      Export secrets from a vault
  get-default-vault Print the default vault
  help              Help about any command
  list-vaults       Print all vaults
  rename-vault      Rename a vault
  search            Search for secrets using regular expressions

Flags:
  -h, --help   help for mrs

Use "mrs [command] --help" for more information about a command.
```

## Configuration

You can use environment variables to customize some settings.

Environment variable | Description
---|---
EDITOR | The editor to use to add or edit secrets (default: nano)
MRS_DEFAULT_VAULT_NAME | The vault to use when `--vault NAME` is not specified (default: the first vault in `${HOME}/.local/share/mrs/vaults`)
MRS_HIDE_EDITOR_INSTRUCTIONS | If set to any value, then the instruction comments will not be included when adding or editing secrets
MRS_HOME | The directory where mrs stores its files (default: `${HOME}/.local/share/mrs`)

## Developing

See the [Makefile](./Makefile).
