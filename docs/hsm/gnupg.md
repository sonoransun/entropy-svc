# GnuPG subprocess

Shells out to `gpg --gen-random <quality> <count>` and captures stdout.
No compile-time dependencies — the `gnupg` feature only adds runtime
subprocess plumbing in `src/entropy/gnupg.rs`.

## Requirements

- `gpg` 2.x in `$PATH` (or at a configured absolute path).
- Build with `--features gnupg`. No system libraries required.

## Quality levels

`gpg --gen-random N count` accepts `N = 0 | 1 | 2`:

| Level | GnuPG meaning |
|---|---|
| `0` | Weak — cheap, suitable for nonces |
| `1` | Strong — session keys |
| `2` | Very strong — long-term keys; may block waiting on system entropy |

Mixrand clamps `quality_level` to `0..=2` in `validate`. Higher levels
may block on low-entropy systems; keep `2` only for daemon-mode feeds
where blocking is acceptable.

## Configuration

```toml
[hsm.gnupg]
enabled = true
gpg_path = "/usr/bin/gpg"    # omit to search $PATH
quality_level = 1
```

```
MIXRAND_GNUPG_ENABLED=true
MIXRAND_GNUPG_GPG_PATH=/usr/bin/gpg
MIXRAND_GNUPG_QUALITY_LEVEL=1
```

## Verification

```
gpg --gen-random 1 32 | xxd
mixrand list-sources | grep gnupg
mixrand -n 32 -f hex
```

## Troubleshooting

- **`gpg: command not found`**: install `gnupg` or set `gpg_path`.
- **Hangs on quality level 2**: this is expected on systems with low
  kernel entropy. Drop to level 1 or feed entropy from another source
  first (e.g., run `mixrand daemon` itself, ironically).
- **Subprocess crashes**: GnuPG prints to stderr; mixrand logs its
  exit status at debug level. Run mixrand with `--log-level debug` to
  see the full error.
