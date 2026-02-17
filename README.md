# Mr. Secretary (mrs) - Organise and secure your secrets

`mrs` is a secrets manager for Linux and macOS.

## Features

- Organise your secrets into one or more encrypted "vaults"
- Edit your secrets using the editor of your choice
- Search through your secrets using regular expressions
- Import and export your secrets
- Encrypt your secrets with [256-bit AES-GCM](https://tools.ietf.org/html/rfc5288)

## Vaults

Each vault is an encrypted text file that contains 0 or more secrets.

A secret is a newline delimited paragraph, where the first line is the search
key and the subsequent lines are the secret value. When searching with
`mrs search` only the key is searched, but you can include a `--full` flag to
search through the full secret contents.

```
$ mrs vault export
Vault password:
a secret key foo
username: user
password: a password

another secret key bar
bank account number: 1234
bank account password: an insecure password

$ mrs search bar
Vault password: 
1 secret(s) matched regular expression "(?i)bar" in vault example

another secret key bar
bank account number: 1234
bank account password: an insecure password
```

## Usage

```
$ mrs help
Mr. Secretary - Organise and secure your secrets

Usage:
  mrs [command]

Examples:
	mrs vault create
	mrs edit
	mrs search secret stuff

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
MRS_TEMP | The directory where `mrs` temporarily stores decrypted files (default `$XDG_RUNTIME_DIR`)

## Developing

See the [Makefile](./Makefile).

### Releasing

This project uses [GoReleaser](https://goreleaser.com/) to automate the release process. To release a new version:

1. Ensure you are on the `main` branch and have pulled the latest changes.
2. Create and push a new semantic version tag:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```
3. The GitHub Actions [release workflow](.github/workflows/release.yml) will automatically trigger, build the binaries, and create a new GitHub Release with the artifacts.
