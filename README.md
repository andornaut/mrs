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
`mrs search` only the key is searched, but you can include a `-f`, `--full`
flag to search through the full secret contents.

When you `mrs add` or `mrs edit`, a few instruction lines are shown at the top
of the editor and removed when you save. Every other line is kept exactly as
you typed it, including indentation, trailing spaces, and lines that begin with
a `#`. Secrets are sorted by key when they are saved. Two secrets may share a
key, and `mrs` prints a warning when they do.

## Naming a vault

`-v`, `--vault` names the vault to work on. A vault whose name matches exactly
is always chosen, whatever longer names begin with it: with `work` and
`work-archive`, `-v work` is `work`. Short of an exact match, how much of a
name is enough depends on what the command does to the vault:

Command | Accepts | A prefix that fits several vaults
--- | --- | ---
`search`, `vault export` | the start of a name | picks the first, and says which
`add`, `edit` | the start of a name | is refused, listing them
`vault change-password`, `vault rename`, `vault delete` | the whole name | is refused, suggesting the closest

Reading the wrong vault shows you something you did not expect; writing to it
leaves a secret where you will not look for it, and renaming, re-keying or
deleting the wrong one cannot be undone from the command that did it.

```text
$ mrs vault export -v alph -p pw
Warning: "alph" begins the name of 2 vaults, so vault alpha was chosen

$ mrs edit -v alph
Error: "alph" begins the name of 2 vaults: alpha, alphabet. Use the whole name of the one you mean
```

Without `-v`, the commands that read or write secrets (`add`, `edit`, `search`
and `vault export`) use `$MRS_DEFAULT_VAULT_NAME`, or the only vault if there
is just one. Unlike `-v`, the configured name has to match a vault exactly: it
is read on every run and looked at almost never, so a typo that reached a
neighbouring vault would go on doing so unnoticed.

`vault create`, `vault change-password`, `vault delete` and `vault rename`
change which vaults exist or what opens them, so they ask which vault rather
than assuming one. With no vaults, or with several and nothing configured,
there is no default to fall back to and `mrs` says so rather than guessing:

```text
$ mrs add
Error: no vaults found. Run "mrs vault create" to create one

$ mrs add
Error: several vaults exist, so there is no default. Use --vault to name one, or set $MRS_DEFAULT_VAULT_NAME
```

## Passwords

`mrs` prompts for a password on the terminal, with echo turned off. When stdin
is not a terminal, as in a script or a cron job, there is nothing to prompt
from, so supply the password in a file instead:

Flag | Command | Supplies
--- | --- | ---
`-p`, `--password-file` | `add`, `edit`, `search`, `vault create`, `vault export`, `vault change-password` | the vault's current password
`-n`, `--new-password-file` | `vault change-password` | the password to change it to
`-i`, `--import-file` | `vault create` | unencrypted secrets to seed the vault with

A short flag means the same thing everywhere: `-p` is always the password file,
`-v` is always the vault, `-y` is always `--yes` and `-f` is always `--full`. A
flag that only some commands have, and that is worth reading twice before
typing, is spelled out in full: `--force`, which deletes another process's lock
file, and `--path`, on `vault list` and `vault get-default`.

A trailing newline is trimmed, so `echo 'a password' > pw` works. Any other
whitespace is part of the password.

Every save first copies the vault to `<name>.<salt>.bak`, so that a write which
goes wrong has something to go back to. After `mrs vault change-password` that
backup is still the version the previous password opens, until the next save
overwrites it. It is written mode 0600 beside a vault the same user already
owns, so it is no more exposed than the vault itself, but delete it if the
password you changed away from is one you no longer trust.

## Confirmations

Emptying a vault with `mrs edit`, and `mrs vault delete`, ask before they go
ahead. `-y`, `--yes` answers in advance.

Without a terminal there is nobody to ask, so `mrs` refuses rather than taking
the safe answer: a command that exits successfully having done nothing reads as
"done" to the script that ran it.

```text
$ mrs vault delete -v old < /dev/null
Error: cannot ask "Delete vault old?": stdin is not a terminal. Use --yes to answer it
```

## Output and exit codes

stdout carries what a caller consumes: the vault names of `vault list` and
`vault get-default`, and the secrets of `vault export` and `search`. Prompts,
warnings, errors and reports of what happened go to stderr, so that
`mrs vault export > secrets` and `mrs search key | less` carry the secrets
alone.

```text
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
1 secret matched "bar" in vault example

another secret key bar
bank account number: 1234
bank account password: an insecure password
```

Exit codes follow `grep`, so that a search which found nothing can be told from
one that could not run:

Code | Meaning
--- | ---
0 | it worked
1 | `mrs search` ran and matched nothing
2 | something went wrong

```text
$ mrs search aws -p pw >/dev/null && echo found || echo none
```

## Usage

```text
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
  completion  Generate the autocompletion script for the specified shell
  edit        Edit secrets in a vault
  help        Help about any command
  search      Search for secrets in a vault
  vault       Manage vaults

Flags:
  -h, --help      help for mrs
      --version   version for mrs

Use "mrs [command] --help" for more information about a command.
```

```text
$ mrs help vault
Manage vaults

Usage:
  mrs vault
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
--- | ---
EDITOR | The editor to use to add or edit secrets (default: nano). May include arguments, such as `vim -n` or `code -w`. Quote a path that contains spaces.
MRS_DEFAULT_VAULT_NAME | The vault that `add`, `edit`, `search` and `vault export` use when `--vault` is not given. Must name a vault exactly (default: the only vault, if there is just one)
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
