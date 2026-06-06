#!/usr/bin/env bash
#
# gps-sf4p17-collector.sh — example collector for mixrand's GPS additional-input.
#
# WHAT THIS IS
#   mixrand can fold the GPS LNAV "Subframe 4, Page 17" Special-Message field
#   (22 bytes / 176 bits) into its output as a NIST SP 800-90A *additional input*
#   (personalization string). See docs/gps-additional-input.md.
#
# WHAT THIS IS NOT
#   The decoded field is PUBLIC broadcast data (~0 bits of real entropy). mixrand
#   credits it 0 entropy bits and never treats it as an entropy source. This script
#   just delivers that public value to mixrand; it does not (and cannot) add
#   randomness. For real entropy, configure a TPM/PKCS#11/HSM/CPU source instead.
#
# CONTRACT
#   The collector must emit EXACTLY 22 bytes (mixrand's expected_len), with
#   NO trailing newline. A longer/shorter value is treated as "unavailable".
#   Because a live Page 17 only repeats once per ~12.5-minute almanac supercycle,
#   keep a CACHED value fresh out-of-band; mixrand reads it quickly and never blocks.
#
# USAGE
#   gps-sf4p17-collector.sh --self-test            # print a fixed 22-byte value (no hardware)
#   gps-sf4p17-collector.sh --file PATH [--interval N]   # (re)write the field to a regular file
#   gps-sf4p17-collector.sh --fifo PATH            # serve the field on a FIFO, forever
#
# WIRING IT TO mixrand
#   examples/gps-sf4p17-collector.sh --self-test > /tmp/sf4p17
#   MIXRAND_GPS_ENABLED=true MIXRAND_GPS_PATH=/tmp/sf4p17 mixrand -n 32 -f hex -v
#
set -euo pipefail

readonly FIELD_LEN=22

# ---------------------------------------------------------------------------
# decode_sf4p17 — produce the latest decoded Subframe 4/Page 17 field (22 bytes).
#
# The default implementation returns a deterministic self-test value so you can
# validate the mixrand wiring with no GNSS hardware. Replace the body with your
# receiver's decode path. Standard NMEA / gpsd does NOT expose raw subframes;
# you need raw nav-message access. Sketches:
#
#   # u-blox via ubxtool (UBX-RXM-SFRBX raw subframe words):
#   ubxtool -p RAW ... | your-sf4p17-parser        # extract the 22 ASCII bytes of page 17
#
#   # gnss-sdr (software-defined receiver) with raw nav-message output:
#   gnss-sdr --config_file=gps_l1.conf ... | your-sf4p17-parser
#
#   # custom RTL-SDR L1 C/A decoder:
#   your-rtlsdr-gps-decoder | your-sf4p17-parser
#
# Whatever you use, the parser must print exactly 22 raw bytes for page 17.
# ---------------------------------------------------------------------------
decode_sf4p17() {
    # ---- SELF-TEST DEFAULT (replace for real hardware) ----
    # Exactly 22 ASCII bytes, emitted with no trailing newline.
    printf '%s' 'MIXRAND-GPS-SELFTEST!!'
}

# Emit the field to stdout, enforcing the 22-byte / no-newline contract.
emit_field() {
    local field
    field="$(decode_sf4p17 | head -c "$FIELD_LEN")"
    if [ "${#field}" -ne "$FIELD_LEN" ]; then
        echo "error: decode_sf4p17 produced ${#field} bytes, expected ${FIELD_LEN}" >&2
        return 1
    fi
    printf '%s' "$field"
}

# Atomically (re)write the field to a regular file.
write_file() {
    local path="$1" tmp
    tmp="$(mktemp "${path}.XXXXXX")"
    emit_field > "$tmp"
    mv -f "$tmp" "$path"
}

usage() { sed -n '2,33p' "$0" >&2; exit "${1:-0}"; }

main() {
    [ "$#" -gt 0 ] || usage 1
    case "$1" in
        --self-test)
            emit_field
            ;;
        --file)
            [ "$#" -ge 2 ] || usage 1
            local path="$2" interval=0
            [ "${3:-}" = "--interval" ] && interval="${4:-0}"
            if [ "$interval" -gt 0 ]; then
                while true; do write_file "$path"; sleep "$interval"; done
            else
                write_file "$path"
            fi
            ;;
        --fifo)
            [ "$#" -ge 2 ] || usage 1
            local path="$2"
            [ -p "$path" ] || mkfifo "$path"
            # Each ">" opens the FIFO (blocks until a reader appears), writes the
            # current field, and closes — exactly matching mixrand's read pattern.
            while true; do emit_field > "$path"; done
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            usage 1
            ;;
    esac
}

main "$@"
