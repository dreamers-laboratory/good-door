# Simple Secure Secret Management for Humans and Agents

We live in an age where there is a game afoot, even though you never agreed to play. You are constantly being attacked, whether you know it or not. And your job is to play defense. So let's kick some ass.

## Why

Attackers rarely break encryption. They read what you left in plaintext: `~/.aws/credentials`, an SSH key with no passphrase, a `.env` in an old backup, or [a token in an agent's transcript](https://www.eweek.com/news/claude-ai-database-wipe/). elbab encrypts all of it in a simple way, keeps each machine's key in its OS vault or chip, and lets agents use credentials they never "see".

## Install

Needs Python 3.9+ and [age](https://github.com/FiloSottile/age) 1.2+.

```sh
git clone https://github.com/dreamers-laboratory/good-door && cd good-door
install -m 755 bin/elbab ~/.local/bin/elbab     # Windows: put bin\elbab and bin\elbab.cmd on PATH
elbab init --recovery ~/elbab-recovery.txt      # then move that file offline
```

## Where the key lives

| OS | `init` option | Notes |
|---|---|---|
| macOS | `--backend keychain` (default) | login Keychain |
| macOS | `--backend secure-enclave` | never leaves the chip; needs `age-plugin-se`; `--access-control passcode` asks for your Mac password at each use |
| Linux | `--backend tpm` (default with a TPM) | systemd-creds 256+; unsealed into RAM once per boot |
| Linux | `--backend secret-service` | GNOME Keyring or KWallet via `secret-tool` |
| Windows | `--backend dpapi` (default) | your Windows account |
| any | `--identity-file PATH` | e.g. a YubiKey plugin identity, which asks for a touch |
| any | `--command CMD` | any CLI that prints the key, e.g. a password manager that asks |

No prompts unless you set the hardware or password manager to ask.

## Use

```sh
elbab set-key openai OPENAI_API_KEY      # prompts; never in shell history (--hidden: no echo)
elbab run openai -- python app.py        # value in the environment, never in a file
elbab print openai                       # all saved fields as JSON
elbab print openai OPENAI_API_KEY        # one value
elbab print openai OPENAI_API_KEY --copy # clipboard, cleared after 30 s
elbab print opnai                        # no match: "did you mean" with every close name
elbab github.com                         # a password; "user / password" stores both
elbab tmp wifi 2h                        # expires
elbab list                               # names only
elbab show keys.json                     # every value, on your own terminal
```

`show` and `csv query` print secrets only to your terminal. Pipes and agent shells (`CLAUDECODE`, `AI_AGENT`,
`CODEX_THREAD_ID`, `CODEX_SHELL` or `CODEX_SANDBOX` set) get them masked; `--mask` masks them on screen too.

`print ENTRY` outputs every saved credential field; add a field name for just its value.
`--copy` works with either form. Existing file and folder paths still print their contents;
use `./NAME` for an explicit relative path. `get` remains a compatibility alias for entry values.
Like `get`, `print` writes secrets directly: agents should use `run`, or pipe directly into the consuming command.

`elbab --help` lists the rest.

## Protect what's already on disk

| Credential | Command | Afterwards |
|---|---|---|
| SSH keys | `elbab ssh-protect ~/.ssh/id_ed25519` | random passphrase; `elbab ssh-load` fills the agent |
| AWS | `elbab aws-protect ~/.aws/credentials` | keyless file; AWS gets keys through `credential_process` |
| gcloud, az | `elbab shims`, shims folder first on PATH, `elbab guard-seal gcloud` | login decrypted only while the CLI runs |
| any CLI | `elbab guard-add kubectl --dir .kube --files config` | same |
| any file or folder | `elbab encrypt ~/wallet` | one age file at the same path; `elbab run ~/wallet -- CMD` decrypts it only while CMD runs |
| `.env` | `elbab import-env app .env && elbab encrypt .env` | `elbab run app -- npm start` |
| unknown | `elbab scan ~/code` | names, never values |

`elbab decrypt PATH` undoes `encrypt`, `elbab print PATH` writes to stdout, and `-o OUT` makes a copy instead (never overwrites). `run` takes a path when it has a slash or starts with `.` or `~`, and keeps the previous version in `backups/` if CMD changed anything. Plain `age -d` (plus `tar` for a folder) always recovers a file without elbab.

SSH without prompts: macOS, add `UseKeychain yes` under `Host *` in `~/.ssh/config`. Headless Linux, use [`contrib/elbab-ssh-agent.service`](contrib/elbab-ssh-agent.service). Windows, start the `ssh-agent` service and run `elbab ssh-load` once.

## Agents

Give your agent [`skill/SKILL.md`](skill/SKILL.md). It runs commands with credentials and never sees them.

## Limits

This is designed to protect against external attackers. With prompts on, even malware running as you, like [this one](https://cursor.com/blog/claude-code-extension-security-notice), can't unlock it on its own. It assumes a trusted agent, and doesn't protect against your agent going rogue at the dawn of the robot apocalypse.

- The default favors convenience and ease of use, since we suspect most people wouldn't use the Fort Knox version: with no prompts, anything running as you can call elbab. For the strongest protection, choose a key that asks for a secret only you know at each use: the Secure Enclave with `--access-control passcode` on macOS, or on any OS a password manager or YubiKey set to ask for its password or PIN every time. That protects you from most attack vectors, as long as you have the secret written down or memorized.
- Prompts don't cover secrets already in use: a running `elbab run` command or a loaded SSH agent.
- `encrypt` replaces originals, but SSDs can keep old blocks. Use full-disk encryption.
- Files and folders: up to 256 MB, no links.
- `--show` and `--dump` export everything after your OS password.

## Test

`python3 -m unittest -v tests/test_elbab.py`. CI on macOS, Linux and Windows runs on demand: `gh workflow run test`.

More about our process: [AI security and red teaming at Dreamers](https://thedreamers.us/ai/ai-security/).

Etymology of ELBAB, for the curious: In Arabic (and sometimes borrowed in Hebrew), "Elbab Maftuch" literally means the door is open, and is an expression of warmth and open invitation to trusted friends and guests who are welcome in one's home.
