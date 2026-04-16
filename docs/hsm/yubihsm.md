# YubiHSM 2

Reads random bytes from a YubiHSM 2 via the `GetPseudoRandom` command
over HTTP to the local `yubihsm-connector`. Implemented in
`src/entropy/yubihsm.rs` using the
[`yubihsm`](https://crates.io/crates/yubihsm) crate (pure Rust, no C
dependency).

## Requirements

- A YubiHSM 2 USB device.
- `yubihsm-connector` daemon installed and running. It's a tiny Go
  binary that multiplexes the USB interface over HTTP.
- An authentication key (ID + password) provisioned on the device.
- Build with `--features yubihsm-native`.

## Connector setup

```
# Install from Yubico SDK package
systemctl enable --now yubihsm-connector

# Verify
curl http://127.0.0.1:12345/connector/status
```

By default the connector listens on `127.0.0.1:12345`. Override via
`yubihsm-connector.yaml` (typically `/etc/yubihsm-connector.yaml`).

## Authentication key

If you do not already have an auth key, initialize one with
`yubihsm-shell` (from the SDK):

```
yubihsm-shell
yubihsm> connect
yubihsm> session open 1 password    # default auth key 1, password "password"
yubihsm> put authkey 0 2 "mixrand" all get-pseudo-random 1234567890abcd
yubihsm> session close 0
```

Store the new password in an env var or secrets manager and remove the
default key.

## Configuration

```toml
[hsm.yubihsm]
enabled = true
connector_url = "http://127.0.0.1:12345"
auth_key_id = 2
# password intentionally omitted; set via env var only.
```

```
MIXRAND_YUBIHSM_ENABLED=true
MIXRAND_YUBIHSM_CONNECTOR_URL=http://127.0.0.1:12345
MIXRAND_YUBIHSM_AUTH_KEY_ID=2
MIXRAND_YUBIHSM_PASSWORD=1234567890abcd   # never commit
```

## Verification

```
# From yubihsm-shell
yubihsm-shell -a get-pseudo-random -l 32 --authkey 2 --password ...

# From mixrand
mixrand list-sources | grep yubihsm
mixrand -n 32 -f hex
```

## Troubleshooting

- **`Unexpected transport error`**: the connector is not reachable.
  Check `systemctl status yubihsm-connector` and the `curl` probe
  above.
- **`CommandError(AuthError)`**: wrong auth key ID or password.
- **`CommandError(SessionsFull)`**: the device keeps at most 16 open
  sessions; close stray sessions from other tools or wait for the
  idle timeout (30 s).
- **`Permission denied` on `/dev/bus/usb/...`**: add a udev rule:

  ```
  # /etc/udev/rules.d/70-yubihsm.rules
  ACTION=="add", SUBSYSTEMS=="usb", ATTRS{idVendor}=="1050", \
      ATTRS{idProduct}=="0030", GROUP="plugdev", MODE="0660"
  ```
