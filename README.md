# Mr. Secretary (mrs) - Organise and secure your secrets

`mrs` is a secrets manager for Linux and macOS.

## Features

- Organise your secrets into one or more encrypted "vaults"
- Edit your secrets using the editor of your choice
- Search through your secrets using regular expressions
- Import and export your secrets
- Encrypt your secrets with [256-bit AES-GCM](https://tools.ietf.org/html/rfc5288)

## Usage

```
$ mrs help
Mr. Secretary - Organise and secure your secrets

Usage:
  mrs [command]

Examples:
	mrs vault create
	mrs edit
	mrs search 'secret stuff'

Available Commands:
  add         Add secrets to a vault
  edit        Edit secrets in a vault
  help        Help about any command
  search      Search for secrets in a vault
  vault       Manage vaults

Flags:
  -h, --help   help for mrs

Use "mrs [command] --help" for more information about a command.
```

```
$ mrs help vault
Manage vaults

Usage:
  mrs vault [command]

Available Commands:
  change-password Change a vault's password
  create          Create a vault
  delete          Delete a vault
  export          Export secrets from a vault
  get-default     Print the default vault
  list            List all vaults
  rename          Rename a vault

Flags:
  -h, --help   help for vault

Use "mrs vault [command] --help" for more information about a command.
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
