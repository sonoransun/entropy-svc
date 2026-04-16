# mixrand deployment files

Drop-in artifacts for running `mixrand daemon` under systemd on a
production host.

## Install paths

| Artifact | Path |
|---|---|
| Binary | `/usr/local/bin/mixrand` |
| Config | `/etc/mixrand.toml` |
| Runtime dir | `/run/mixrand/` |
| PID file | `/run/mixrand/mixrand.pid` |
| Systemd unit | `/etc/systemd/system/mixrand.service` |
| tmpfiles.d | `/usr/lib/tmpfiles.d/mixrand.conf` |

## One-time setup

```
# Build and install the binary (adjust target if cross-compiling)
cargo build --release
install -m 0755 target/release/mixrand /usr/local/bin/mixrand

# Create the unprivileged account the daemon drops to
useradd --system --no-create-home --shell /usr/sbin/nologin mixrand

# Install systemd + tmpfiles artifacts
install -m 0644 deploy/systemd/mixrand.service /etc/systemd/system/mixrand.service
install -m 0644 deploy/systemd/mixrand.tmpfiles.d.conf /usr/lib/tmpfiles.d/mixrand.conf
systemd-tmpfiles --create mixrand.conf

# Install a starter config
install -m 0644 docs/config.example.toml /etc/mixrand.toml

systemctl daemon-reload
systemctl enable --now mixrand
```

## Verify

```
systemctl status mixrand
journalctl -u mixrand -f                # tail live logs
cat /proc/sys/kernel/random/entropy_avail   # pool level rises after inject
mixrand check --duration 5s                 # per-source health snapshot
```

## Signals

- `SIGTERM` / `SIGINT`: graceful shutdown, PID file removed.
- `SIGHUP`: reload `/etc/mixrand.toml`. Does NOT reopen `/dev/random`, the
  pid file, or re-probe source plugins — restart the unit for a full
  refresh.

## Capabilities

The unit keeps `CAP_SYS_ADMIN`, `CAP_IPC_LOCK`, `CAP_SETUID`, and
`CAP_SETGID` in the capability bounding set. The daemon needs:

| Capability | Purpose |
|---|---|
| `CAP_SYS_ADMIN` | `ioctl(RNDADDENTROPY)` on `/dev/random` |
| `CAP_IPC_LOCK` | `mlockall` to pin entropy buffers out of swap |
| `CAP_SETUID` / `CAP_SETGID` | drop to `--user mixrand` at start-up |

## Uninstall

```
systemctl disable --now mixrand
rm /etc/systemd/system/mixrand.service
rm /usr/lib/tmpfiles.d/mixrand.conf
rm /usr/local/bin/mixrand
userdel mixrand
rm -rf /run/mixrand
# Keep /etc/mixrand.toml if you want config continuity across reinstalls.
```
