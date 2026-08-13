# Mr. Secretary (mrs)

A command line secrets manager for Linux and macOS. Secrets are organised into
encrypted vaults: one file each, edited in `$EDITOR`, searched with regular
expressions.

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

Command | Does | Vault name
--- | --- | ---
`mrs add` | Add secrets in an editor | a prefix that fits one
`mrs edit` | Edit secrets in an editor | a prefix that fits one
`mrs search <regular expression>...` | Print matching secrets | a prefix
`mrs vault list` | Print vault names | -
`mrs vault get-default` | Print the default vault | -
`mrs vault create` | Create a vault | a new name
`mrs vault export` | Print every secret | a prefix
`mrs vault change-password` | Re-encrypt under a new password | the whole name
`mrs vault rename <source> <target>` | Rename a vault | the whole name
`mrs vault delete` | Delete a vault, after confirming | the whole name

`search` matches keys only, unless `--full`. Matching is case insensitive, and
arguments are joined, so `mrs search bank account` matches `bank account`.
`mrs --version` prints the version, and `-h`, `--help` works on every command.

## Flags

Flag | Commands | Supplies
--- | --- | ---
`-v`, `--vault` | all but `vault list`, `vault get-default` and `vault rename` | the vault's name
`-p`, `--password-file` | `add`, `edit`, `search`, `vault create`, `vault export`, `vault change-password` | the vault's current password
`-n`, `--new-password-file` | `vault change-password` | the password to change it to
`-i`, `--import-file` | `vault create` | unencrypted secrets to seed the vault with
`-f`, `--full` | `search` | match values as well as keys
`-y`, `--yes` | `edit`, `vault delete` | the answer to the confirmation
`--force` | `add`, `edit`, `vault create`, `vault change-password`, `vault delete`, `vault rename` | permission to delete another process's lock file
`--path` | `vault list`, `vault get-default` | paths instead of names

A short flag means the same thing on every command. `--force` and `--path` have
no short form, because both are worth spelling out.

## Naming a vault

An exact name always wins, whatever longer names begin with it: with `work` and
`work-archive`, `-v work` is `work`. Otherwise a prefix is treated according to
what the command does to the vault:

Commands | A prefix that fits several vaults
--- | ---
`search`, `vault export` | picks the first, and says which
`add`, `edit` | is refused, listing them
`vault change-password`, `vault rename`, `vault delete` | is refused, suggesting the closest

Without `-v`:

- `add`, `edit`, `search` and `vault export` use `$MRS_DEFAULT_VAULT_NAME`, or
  the only vault if there is just one. Unlike `-v`, the configured name has to
  match exactly.
- No vaults, or several with nothing configured, is an error rather than a
  guess.
- The other `mrs vault` commands ask which vault.

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
$ mrs vault delete -v old < /dev/null
Error: cannot ask "Delete vault old?": stdin is not a terminal. Use --yes to answer it
```

## Output and exit codes

stdout carries what a caller consumes: vault names from `vault list` and
`vault get-default`, secrets from `vault export` and `search`. Prompts,
warnings, errors and reports go to stderr, so `mrs vault export > secrets` and
`mrs search key | less` carry the secrets alone.

```text
$ mrs search bar
Vault password:
1 secret matched "bar" in vault example

another secret key bar
bank account number: 1234
```

Exit codes follow `grep`:

Code | Meaning
--- | ---
0 | it worked
1 | `mrs search` ran and matched nothing
2 | something went wrong

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

- [256-bit AES-GCM](https://tools.ietf.org/html/rfc5288).
- PBKDF2-SHA256, 600,000 iterations, over a 32 character salt that is unique per
  vault and carried in its filename.
- Vaults written with the earlier 4,096 iterations are still read, and are
  re-encrypted at 600,000 on the next save.

## Developing

See the [Makefile](./Makefile).

To release, push a semantic version tag from `main`:

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

The [release workflow](.github/workflows/release.yml) runs the tests, then
builds and publishes the binaries with [GoReleaser](https://goreleaser.com/).
Every push to `main` republishes the rolling `dev` release the same way.
