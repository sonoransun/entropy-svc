# Production Deployment

Run `mixrand daemon` under systemd with hardening flags appropriate for
a service that feeds the kernel entropy pool.

## Prerequisites

- Linux kernel 3.18+ (for `getrandom(2)`) — any distro released since
  2015.
- systemd 230+ for the full hardening directive set; 245+ for the
  watchdog behavior used in our unit.
- Rust toolchain to build from source (MSRV: 1.74).
- Root (or `CAP_SYS_ADMIN` + `CAP_IPC_LOCK` + `CAP_SETUID/SETGID` via
  ambient caps) to install and start the service.

## Install paths

| Artifact | Path |
|---|---|
| Binary | `/usr/local/bin/mixrand` |
| Config | `/etc/mixrand.toml` |
| Runtime dir | `/run/mixrand/` |
| PID file | `/run/mixrand/mixrand.pid` |
| Systemd unit | `/etc/systemd/system/mixrand.service` |
| tmpfiles.d | `/usr/lib/tmpfiles.d/mixrand.conf` |
| Logs | `journalctl -u mixrand` |

## User / group

```
groupadd --system mixrand
useradd --system --gid mixrand --no-create-home --shell /usr/sbin/nologin mixrand
```

The daemon runs as root briefly at start-up (to open `/dev/random` for
writing and install signal handlers) and then drops to this account
before entering the main loop. If your deployment does not need
`--user`, delete the `--user mixrand` argument from the unit and the
daemon stays as root — which is fine for a small fleet but not
recommended for shared infrastructure.

## Install the unit

```
install -m 0755 target/release/mixrand /usr/local/bin/mixrand
install -m 0644 deploy/systemd/mixrand.service /etc/systemd/system/mixrand.service
install -m 0644 deploy/systemd/mixrand.tmpfiles.d.conf /usr/lib/tmpfiles.d/mixrand.conf
install -m 0644 docs/config.example.toml /etc/mixrand.toml
systemd-tmpfiles --create mixrand.conf
systemctl daemon-reload
systemctl enable --now mixrand
```

## Hardening directives in the unit

The shipped unit enables most of the systemd sandboxing knobs. Each
directive is chosen deliberately:

| Directive | Purpose |
|---|---|
| `NoNewPrivileges=yes` | blocks `setuid` escalation for the daemon or anything it fork-execs |
| `ProtectSystem=strict` | read-only root filesystem view |
| `ProtectHome=yes` | `/home` invisible — daemon has no reason to touch it |
| `PrivateTmp=yes` | per-service /tmp namespace |
| `ProtectKernelModules=yes` | cannot `finit_module`/`delete_module` |
| `ProtectControlGroups=yes` | cannot modify cgroup v2 state |
| `LockPersonality=yes` | no `personality(2)` changes |
| `MemoryDenyWriteExecute=yes` | W^X for all mappings |
| `RestrictRealtime=yes` | no SCHED_FIFO/SCHED_RR |
| `RestrictSUIDSGID=yes` | blocks creating SUID binaries |
| `RestrictNamespaces=yes` | no clone/unshare of new namespaces |
| `SystemCallArchitectures=native` | blocks 32-bit syscall interface on amd64 |
| `SystemCallFilter=@system-service` | seccomp allowlist |
| `DeviceAllow=/dev/random rw` | explicit allow — needed for RNDADDENTROPY |
| `DeviceAllow=/dev/hwrng r` | explicit allow — hardware RNG source |
| `DeviceAllow=/dev/urandom r` | explicit allow — fallback seed |
| `CapabilityBoundingSet=…` | drops every capability the daemon doesn't use |

## Capabilities required

| Capability | Purpose |
|---|---|
| `CAP_SYS_ADMIN` | `ioctl(RNDADDENTROPY)` on `/dev/random` |
| `CAP_IPC_LOCK` | `mlockall` to pin entropy buffers out of swap |
| `CAP_SETUID` / `CAP_SETGID` | drop to `--user mixrand` after opening `/dev/random` |

Dropping `CAP_SYS_ADMIN` turns the daemon into a no-op — it can
generate entropy but cannot inject.

## Verification procedure

After `systemctl start mixrand`:

```
# Unit is active and systemd saw the READY notification
systemctl status mixrand

# Tail the startup log to confirm the self-test ran
journalctl -u mixrand -n 50 -p info

# Kernel entropy pool level should rise after injects
watch -n 1 cat /proc/sys/kernel/random/entropy_avail

# Per-source health snapshot from the same binary
mixrand check --duration 5s --json
```

Look for lines like `self-test: <source> OK (256 bytes)` and periodic
`injected 64B (256bits credit) from <source>, entropy was ...bits`.

## Upgrades

```
install -m 0755 target/release/mixrand /usr/local/bin/mixrand
systemctl restart mixrand       # no daemon-reload needed if unit unchanged
```

Upgrade is seamless — `systemctl restart` SIGTERMs the old daemon,
which cleanly removes the PID file and exits, then starts the new one.
`Type=notify` holds systemd back until READY, so the "down" window is
measured in hundreds of milliseconds.

## Rollback

Keep the previous binary around if in doubt:

```
cp /usr/local/bin/mixrand /usr/local/bin/mixrand.prev
install -m 0755 target/release/mixrand /usr/local/bin/mixrand
systemctl restart mixrand
# Revert if needed
cp /usr/local/bin/mixrand.prev /usr/local/bin/mixrand
systemctl restart mixrand
```

## SIGHUP reload semantics

`SIGHUP` re-reads `/etc/mixrand.toml` and applies parseable changes to
the daemon's in-memory config — primarily thresholds, intervals, and
cpu-RNG tuning. The reload does **not**:

- Re-probe source plugins (e.g., a freshly plugged YubiKey is not
  picked up — restart the service).
- Reopen the `/dev/random` file descriptor.
- Move the PID file.
- Re-run the startup self-test.

If those are what you need, `systemctl restart mixrand`.

## Production checklist

- [ ] Binary built with `cargo build --release` (LTO + symbol strip).
- [ ] Config file owned by `root:root`, mode `0644`, no world-readable
      secrets. Put PINs / passwords in `MIXRAND_*` env vars only.
- [ ] Systemd unit installed, enabled, started.
- [ ] tmpfiles.d entry installed and `/run/mixrand` exists after boot.
- [ ] `mixrand check --duration 10s` shows every expected source as
      healthy.
- [ ] `journalctl -u mixrand --since "5 min ago"` shows inject events
      at the configured cadence.
- [ ] `/proc/sys/kernel/random/entropy_avail` rises past the
      configured threshold within one `interval`.
- [ ] `systemctl kill -s HUP mixrand` logs a `SIGHUP received,
      reloading config` line.
