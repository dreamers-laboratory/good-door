---
name: elbab
description: Use credentials kept in elbab, the age-encrypted local store, without exposing them. Use when a task needs an API key, password, token, SSH key, cloud CLI login or .env value, or when a credential should be stored or protected.
---

# elbab

You use credentials. You never see them.

## Rules

- Find names with `elbab list`. Use a value with `elbab run ENTRY -- CMD`.
- Never print, echo, log or write a value, or pass one as an argument. `elbab get` and `elbab print` only when piped straight into the command that needs it.
- Never read `*.age` files, the machine identity or private key files. Never use `--reveal`, `--show` or `--dump`, and never run elbab in a terminal the user shares with you: `show` and `csv query` print secrets there. In your own shell they print masked; if they don't, stop and tell the user.
- To store a new secret, ask the user to run `elbab set-key ENTRY VAR` or `elbab NAME` in their own terminal. Don't type it yourself.
- Run `elbab verify` after any change to the store.

## Credentials

| Need | Do |
|---|---|
| API key, token | `elbab run ENTRY -- CMD` |
| `.env` values | `elbab run ENTRY -- CMD`; store a file with `elbab import-env ENTRY FILE` |
| SSH, git, scp | work as usual. Load keys with `elbab ssh-load KEY`, never `ssh-add KEY` |
| new SSH key | `elbab ssh-protect KEY` |
| public key | `elbab pubkeys NAME` |
| AWS | `--profile` or `AWS_SHARED_CREDENTIALS_FILE` as usual; after `aws configure` writes keys, `elbab aws-protect FILE` |
| gcloud, az, guarded CLIs | run as usual (shims); after a login outside the shim, `elbab guard-seal TOOL` |
| encrypted file or folder (starts with `age-encryption.org/v1`) | `elbab run PATH -- CMD`. `elbab decrypt PATH` only with the user's OK, then `elbab encrypt PATH` when done |
| loose secret files | `elbab scan PATH` lists them. Report them; `elbab encrypt PATH` only with the user's OK |

## Errors

- `not set up`: the user runs `elbab init`.
- `cannot decrypt`: this machine is not a recipient; the user adds it (`elbab recipients add`, `elbab rekey`).
- `unknown or expired entry`: check `elbab list`; ask the user.
