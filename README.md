# Mr. Secretary (mrs)

[![Test](https://github.com/andornaut/mrs/actions/workflows/test.yml/badge.svg)](https://github.com/andornaut/mrs/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/license/MIT)

A command line secrets manager for Linux and macOS. Secrets are organised into
encrypted vaults: one file each, edited in `$VISUAL` or `$EDITOR`, searched
with regular expressions.

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

- A vault holds secrets separated by blank lines. A line of nothing but spaces
  or tabs separates them too, and is written back as a blank one.
- The first line of a secret is its key; the rest is its value.
- Every other line is kept as typed: indentation, trailing spaces, and lines
  that begin with a `#`.
- Secrets are sorted by key, ignoring case, when saved. Two may share a key, and
  `mrs` warns when they do, on import as well as on save.
- A file given to `vault create --import-file` is stored as it is written, so it
  keeps its own order until the vault is next saved.
- `mrs add` and `mrs edit` open `$VISUAL` or `$EDITOR` on the secrets alone,
  and encrypt whatever the editor saves. `mrs add --help` states the format.

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
`vault list` prints names sorted ignoring case, as secrets are sorted by key.
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
`--force` | `add`, `edit`, `vault create`, `vault change-password`, `vault delete`, `vault rename` | permission to repair a lock file that cannot be used
`--path` | `vault list`, `vault default` | paths instead of names

A short flag means the same thing on every command. `--force` and `--path` have
no short form, because both are worth spelling out.

`--force` repairs a lock file that cannot be opened, because its mode forbids
it, a directory sits in its place, or it is a symlink into a directory that is
not there. It never takes a lock another process holds:
taking one would mean deleting the lock file, leaving the two processes holding
two different files. A held lock is refused with or without the flag:

```console
$ mrs vault delete work --force --yes
Error: vault work is currently locked by another process. --force repairs a lock
file that cannot be used, and does not take a lock another process holds
```

Wait for the other process, or stop it. A lock file left behind by a process
that died needs neither: it is already re-lockable.

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

- Prompted on the terminal with echo off. At least 8 characters, and no
  newline. A password mrs will not accept is refused before it asks you to
  confirm it.
- Without a terminal there is nothing to prompt from, so pass
  `--password-file`. A trailing newline is trimmed, so `echo 'pw' > pw` works;
  other whitespace is part of the password.
- Saving an existing vault first copies it to `<name>.<salt>.bak`. After
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
`vault default`, secrets from `export` and `search`. Warnings, errors and
reports go to stderr, so `mrs export > secrets` and `mrs search key | less`
carry the secrets alone. Prompts go to the terminal itself, so that redirecting
stderr does not leave `mrs` waiting for an answer nobody can see.

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
`$MRS_HOME/vaults/<name>.lock` | the lock on the name, empty
`$MRS_TEMP/mrs/<run>/` | decrypted secrets while an editor is open, mode 0700

The vault directory is mode 0700. `mrs` narrows permissions it finds wider than
that and never widens them. One process at a time may write a vault or claim its
name; reads take no lock, and every write is atomic, so a reader never sees a
half-written vault. A lock file outlives the vault it is named for, because
removing it would leave two processes holding two different files. The temporary
directory is created only when secrets are decrypted, and removed when `mrs`
exits, including on SIGHUP, SIGINT, SIGQUIT and SIGTERM. A SIGKILL or a power
loss leaves the decrypted file behind, because nothing runs to remove it, and no
later run sweeps it up; delete it by hand.

A file in the vault directory that is not shaped like a vault is named on stderr
and otherwise left alone. A vault that mrs cannot read is a different thing: a
symlink whose target is not there, a directory where a file should be, or a
vault written by a release that derived its key differently. Those are listed
with a warning saying why, keep their names, and can be renamed or deleted like
any other; only the commands that have to read them fail.

## Configuration

Environment variable | Description
--- | ---
`EDITOR` | The editor `add` and `edit` open, if `$VISUAL` is unset (default: `nano`). May carry arguments, such as `vim -n`. Quote a path that contains spaces.
`MRS_DEFAULT_VAULT_NAME` | The vault to use when `--vault` is not given. Must name one exactly (default: the only vault, if there is just one).
`MRS_HOME` | Where vaults are stored (default: `$XDG_DATA_HOME/mrs`, else `$HOME/.local/share/mrs`).
`MRS_TEMP` | Where decrypted secrets are written while an editor is open (default: `$XDG_RUNTIME_DIR`, else the system temporary directory).
`VISUAL` | The editor `add` and `edit` open, in preference to `$EDITOR`. Same form.

## Encryption

- [256-bit AES-GCM](https://datatracker.ietf.org/doc/html/rfc5288).
- PBKDF2-SHA256, 600,000 iterations, over a 32 character salt that is unique per
  vault and carried in its filename.
- Vaults written with the earlier 4,096 iterations are not read. Every release
  up to v0.1.7 reads one and re-encrypts it at 600,000 iterations on the next
  save, so open and save such a vault with one of those before upgrading.

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

The [test workflow](.github/workflows/test.yml) runs the tests and
`golangci-lint` on every branch and pull request. The
[release workflow](.github/workflows/release.yml) calls it, then builds and
publishes the binaries with [GoReleaser](https://goreleaser.com/). Every push to
`main` republishes the rolling `dev` release the same way.
