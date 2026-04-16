# YubiKey

Reads random bytes from a YubiKey over PC/SC using the PIV applet's
`GET CHALLENGE` APDU. Implemented in `src/entropy/yubikey.rs`, building
on the generic PC/SC source with YubiKey-specific ATR detection and
applet selection.

## Requirements

- A YubiKey (4, 5, Bio, or later). Older YubiKey NEO models also respond
  but are not officially tested.
- `pcscd` running on the host. `systemctl enable --now pcscd`.
- `libpcsclite-dev` (Debian) / `pcsc-lite-devel` (Fedora) for the
  compile-time link; the runtime needs `libpcsclite.so` only.
- Optional: `ykman` or `yubikey-manager` for slot inspection.

## Setup

Plug the key in and confirm PC/SC sees it:

```
pcsc_scan                  # prints ATR + reader name
ykman info
ykman piv info
```

No PIV re-initialization is required — `GET CHALLENGE` is always
available on the PIV applet without authentication.

Mixrand uses the first YubiKey-shaped reader it finds by default. To
target a specific device when multiple are plugged in, set a serial or
reader-name filter:

```toml
[hsm.yubikey]
enabled = true
serial = 12345678     # 0 = any (default)
```

```
MIXRAND_YUBIKEY_ENABLED=true
MIXRAND_YUBIKEY_SERIAL=12345678
```

## Verification

```
mixrand list-sources | grep -i yubikey
mixrand -n 32 -f hex    # first-available cascade; YubiKey is prio 7
```

## Troubleshooting

- **Reader not detected**: ensure `pcscd` is running and the YubiKey is
  plugged into a USB port (not a hub that blocks CCID).
- **`SCardConnect` returns 0x8010000B (SHARING_VIOLATION)**: another
  process holds an exclusive session (e.g., `ssh-agent`, GPG pinentry).
  Close that process or use mixrand's shared-mode behavior (default).
- **ATR mismatch**: mixrand only uses the PIV applet, not the OpenPGP
  applet. If you have a non-standard applet layout, use the generic
  `pcsc` source instead.
- **Not appearing in `list-sources`**: compile with `--features
  yubikey`. The build implicitly adds `pcsc`.
