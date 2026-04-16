# Generic PC/SC Smart Card

The `pcsc` feature sends an ISO 7816 `GET CHALLENGE` APDU to any PC/SC
reader that responds to it. Works with OpenPGP cards, JavaCard applets,
Estonian ID cards, and smart cards that implement the challenge command
per ISO 7816-4 §7.5.3. Implemented in `src/entropy/pcsc.rs`.

## Requirements

- `pcscd` running on the host.
- `libpcsclite-dev` at build time (Debian/Ubuntu) or
  `pcsc-lite-devel` (Fedora/RHEL).
- At least one reader + card combination that responds to
  `00 84 00 00 Le` (INS=GET_CHALLENGE).

## Setup

```
systemctl enable --now pcscd
pcsc_scan
```

`pcsc_scan` prints each reader's name (for filtering) and ATR (for
identification).

### Reader filtering

If multiple readers are plugged in, restrict mixrand to one by
substring match on the reader name:

```toml
[hsm.pcsc]
enabled = true
reader = "ACS ACR122"    # substring; matches "ACS ACR122U PICC Interface"
max_le = 32              # bytes per APDU (clamped to 1..=255)
```

```
MIXRAND_PCSC_ENABLED=true
MIXRAND_PCSC_READER=ACS ACR122
MIXRAND_PCSC_MAX_LE=32
```

`max_le` controls the `Le` byte in the GET CHALLENGE APDU. Some cards
cap this below 256; `0` is clamped to `1` and `>255` to `255` (see
`src/config.rs::HsmConfig::validate`).

## Verification

```
# With opensc-tool
opensc-tool --reader 0 --send-apdu '00:84:00:00:20' | tail -1

# With mixrand
mixrand list-sources | grep pcsc
mixrand -n 32 -f hex
```

## OpenPGP card example

An OpenPGP card (YubiKey OpenPGP applet, GnuPG ADT cards, Nitrokey Pro)
implements GET CHALLENGE on the OpenPGP applet but mixrand does not
SELECT an applet by default — it queries whatever applet the card
currently exposes. If the applet on reset is not OpenPGP, you may need
the YubiKey-specific source (which explicitly SELECTs PIV) or a custom
preload step.

## Troubleshooting

- **No readers visible**: `systemctl status pcscd` and `lsusb` to
  confirm the reader is enumerated. SCM Microsystems and ACS readers
  occasionally need the `pcsc-ccid` driver package installed
  separately.
- **`SCardTransmit` returns 0x6D00 (INS_NOT_SUPPORTED)**: the currently
  selected applet does not implement GET CHALLENGE. Use a different
  card, a different applet, or the YubiKey source.
- **`SHARING_VIOLATION` with pcscd**: another process holds the card
  exclusively (common with GPG agent). Close it or run mixrand first.
