# Mr. Secretary (mrs)

[![CI](https://github.com/andornaut/mrs/actions/workflows/release.yml/badge.svg)](https://github.com/andornaut/mrs/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A command line secrets manager for Linux and macOS. Secrets are organised into
encrypted vaults: one file each, edited in `$EDITOR`, searched with regular
expressions.

## Installation

Archives are published on the
[releases page](https://github.com/andornaut/mrs/releases): one per tagged
version, plus a `dev` release rebuilt on every push to `main`.

Platform | Asset
--- | ---
Linux x86_64 | `mrs_linux_x86_64.tar.gz`
Linux arm64 | `mrs_linux_arm64.tar.gz`
macOS Apple Silicon | `mrs_darwin_arm64.tar.gz`

The archive carries `LICENSE` and `README.md` alongside the binary, so name the
binary rather than extracting everything into the current directory:

```bash
tar -xzf mrs_linux_x86_64.tar.gz mrs
sudo install -m 755 mrs /usr/local/bin/mrs
```

To compile from source, with [Go](https://go.dev/doc/install) and
[Make](https://www.gnu.org/software/make/):

```bash
git clone https://github.com/andornaut/mrs.git
cd mrs
make install
```

## Secrets

- A vault holds secrets separated by blank lines.
- The first line of a secret is its key; the rest is its value.
- Every line is kept as typed: indentation, trailing spaces, and lines that
  begin with a `#`.
- Secrets are sorted by key, ignoring case, when saved. Two may share a key, and
  `mrs` warns when they do.
- `mrs add` and `mrs edit` open `$EDITOR` on three instruction lines, which are
  removed on save wherever they end up in the buffer.

## Commands

Commands that read or write the secrets in a vault name it with `--vault`,
which accepts a prefix. Commands that create, rename or destroy a vault take
its whole name as an argument.

Command | Does
--- | ---
`mrs add` | Add secrets in an editor
`mrs edit` | Edit secrets in an editor
`mrs search <regular expression>...` | Print matching secrets
`mrs export` | Print every secret
`mrs vault list` | Print vault names
`mrs vault default` | Print the default vault
`mrs vault create <name>` | Create a vault
`mrs vault change-password <name>` | Re-encrypt under a new password
`mrs vault rename <source> <target>` | Rename a vault
`mrs vault delete <name>` | Delete a vault, after confirming

`search` matches keys only, unless `--full`. Matching is case insensitive, and
arguments are joined, so `mrs search bank account` matches `bank account`.
`mrs --version` prints the version, and `-h`, `--help` works on every command.

## Flags

Flag | Commands | Supplies
--- | --- | ---
`-v`, `--vault` | `add`, `edit`, `search`, `export` | the vault's name, or the start of it
`-p`, `--password-file` | `add`, `edit`, `search`, `export`, `vault create`, `vault change-password` | the vault's current password
`-n`, `--new-password-file` | `vault change-password` | the password to change it to
`-i`, `--import-file` | `vault create` | unencrypted secrets to seed the vault with
`-f`, `--full` | `search` | match values as well as keys
`-y`, `--yes` | `edit`, `vault delete` | the answer to the confirmation
`--force` | `add`, `edit`, `vault create`, `vault change-password`, `vault delete`, `vault rename` | permission to delete another process's lock file
`--path` | `vault list`, `vault default` | paths instead of names

A short flag means the same thing on every command. `--force` and `--path` have
no short form, because both are worth spelling out.

## Naming a vault

`add`, `edit`, `search` and `export` name a vault with `-v`, which takes a
prefix. An exact name always wins, whatever longer names begin with it: with
`work` and `work-archive`, `-v work` is `work`. Short of one, a prefix has to
fit exactly one vault:

```text
$ mrs edit -v alph
Error: "alph" begins the name of 2 vaults: alpha, alphabet. Use the whole name of the one you mean
```

Without `-v`, those four use `$MRS_DEFAULT_VAULT_NAME`, or the only vault if
there is just one. Unlike `-v`, the configured name has to match exactly. No
vaults, or several with nothing configured, is an error rather than a guess.

`vault create`, `vault change-password`, `vault rename` and `vault delete` name
the vault as an argument instead, and take no prefix at all: each one creates,
re-keys, moves or destroys a vault, so a name short of the whole thing must not
reach a neighbouring one. They name the closest vault when given a prefix:

```text
$ mrs vault delete alph
Error: vault "alph" not found. Did you mean "alpha"?
```

Names may hold ASCII letters, digits, `_` and `-`, up to 200 characters.

## Passwords

- Prompted on the terminal with echo off, and at least 8 characters long.
- Without a terminal there is nothing to prompt from, so pass
  `--password-file`. A trailing newline is trimmed, so `echo 'pw' > pw` works;
  other whitespace is part of the password.
- Every save first copies the vault to `<name>.<salt>.bak`. After
  `vault change-password` that backup still opens with the old password until
  the next save, so delete it if that password is no longer trusted.

## Confirmations

`mrs edit` that would empty a vault, and `mrs vault delete`, ask first.
`-y`, `--yes` answers in advance. Without a terminal and without `--yes`, `mrs`
fails rather than assume an answer:

```text
$ mrs vault delete old < /dev/null
Error: cannot ask "Delete vault old?": stdin is not a terminal. Use --yes to answer it
```

## Output and exit codes

stdout carries what a caller consumes: vault names from `vault list` and
`vault default`, secrets from `export` and `search`. Prompts, warnings, errors
and reports go to stderr, so `mrs export > secrets` and `mrs search key | less`
carry the secrets alone.

```text
$ mrs search bar
Vault password:
1 secret matched "bar" in vault example

another secret key bar
bank account number: 1234
```

Code | Meaning
--- | ---
0 | it worked
1 | it failed
2 | it was typed wrong: no command, an unknown command or flag, or a missing or extra argument
3 | `mrs search` ran and matched nothing
128+n | a signal ended it: 129 SIGHUP, 130 SIGINT, 131 SIGQUIT, 143 SIGTERM

A wrong invocation prints the usage that would have been right; a command that
ran and failed does not. `mrs --help` writes help to stdout and reports success.

## Files

Path | Holds
--- | ---
`$MRS_HOME/vaults/<name>.<salt>` | the vault, mode 0600
`$MRS_HOME/vaults/<name>.<salt>.bak` | the version before the last save
`$MRS_HOME/vaults/<name>.lock` | the write lock, empty
`$MRS_TEMP/mrs/<run>/` | decrypted secrets while an editor is open, mode 0700

The vault directory is mode 0700. `mrs` narrows permissions it finds wider than
that and never widens them. The temporary directory is removed when `mrs` exits,
including on SIGHUP, SIGINT, SIGQUIT and SIGTERM.

## Configuration

Environment variable | Description
--- | ---
`EDITOR` | The editor `add` and `edit` open (default: `nano`). May carry arguments, such as `vim -n`. Quote a path that contains spaces.
`MRS_DEFAULT_VAULT_NAME` | The vault to use when `--vault` is not given. Must name one exactly (default: the only vault, if there is just one).
`MRS_HIDE_EDITOR_INSTRUCTIONS` | If set to any value, omit the instruction lines from editor sessions.
`MRS_HOME` | Where vaults are stored (default: `$XDG_DATA_HOME/mrs`, else `$HOME/.local/share/mrs`).
`MRS_TEMP` | Where decrypted secrets are written while an editor is open (default: `$XDG_RUNTIME_DIR`, else the system temporary directory).

## Encryption

- [256-bit AES-GCM](https://datatracker.ietf.org/doc/html/rfc5288).
- PBKDF2-SHA256, 600,000 iterations, over a 32 character salt that is unique per
  vault and carried in its filename.
- Vaults written with the earlier 4,096 iterations are still read, and are
  re-encrypted at 600,000 on the next save.

The AES-GCM seal and open in [`internal/crypto`](./internal/crypto/crypto.go)
are copied from [cryptopasta](https://github.com/gtank/cryptopasta), which its
author placed in the public domain under CC0 to be copied rather than imported.
The ciphertext is `nonce|ciphertext|tag` with a random 96-bit nonce per save.

## Developing

See the [Makefile](./Makefile). `make test` runs both layers:

- [`internal/`](./internal) holds unit tests, beside the code they exercise.
- [`test/e2e`](./test/e2e) drives a compiled `mrs` against real vault files, a
  real editor process and real encryption. Nothing is mocked. Each test gets its
  own vault, temporary and home directories, so they run in parallel; the
  [fake editor](./test/e2e/testdata/fakeeditor) is scripted through the
  environment, and the cases that answer a prompt run `mrs` on a pseudo-terminal,
  because without one it reports that it cannot ask.

To release, push a semantic version tag from `main`:

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

The [release workflow](.github/workflows/release.yml) runs the tests, then
builds and publishes the binaries with [GoReleaser](https://goreleaser.com/).
Every push to `main` republishes the rolling `dev` release the same way.
