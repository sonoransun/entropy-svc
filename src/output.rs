use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use crate::cli::OutputFormat;

/// Writes the random bytes to stdout or a file in the specified format.
pub fn write_output(
    bytes: &[u8],
    format: &OutputFormat,
    output_file: Option<&Path>,
) -> io::Result<()> {
    match output_file {
        Some(path) => {
            let f = File::create(path)?;
            let mut out = BufWriter::new(f);
            format_output(bytes, format, &mut out)?;
            out.flush()
        }
        None => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            format_output(bytes, format, &mut out)?;
            out.flush()
        }
    }
}

fn format_output(bytes: &[u8], format: &OutputFormat, out: &mut dyn Write) -> io::Result<()> {
    match format {
        OutputFormat::Hex => {
            for b in bytes {
                write!(out, "{:02x}", b)?;
            }
            writeln!(out)?;
        }
        OutputFormat::HexUpper => {
            for b in bytes {
                write!(out, "{:02X}", b)?;
            }
            writeln!(out)?;
        }
        OutputFormat::Raw => {
            out.write_all(bytes)?;
        }
        OutputFormat::Base64 => {
            writeln!(out, "{}", STANDARD.encode(bytes))?;
        }
        OutputFormat::Base64url => {
            writeln!(out, "{}", URL_SAFE_NO_PAD.encode(bytes))?;
        }
        OutputFormat::Uuencode => {
            write_uuencode(bytes, out)?;
        }
        OutputFormat::Text => {
            write_printable_text(bytes, out)?;
        }
        OutputFormat::Octal => {
            let parts: Vec<String> = bytes.iter().map(|b| format!("{:03o}", b)).collect();
            writeln!(out, "{}", parts.join(" "))?;
        }
        OutputFormat::Binary => {
            let parts: Vec<String> = bytes.iter().map(|b| format!("{:08b}", b)).collect();
            writeln!(out, "{}", parts.join(" "))?;
        }
    }
    Ok(())
}

/// Maps random bytes into printable ASCII characters (33..=126, i.e. '!' through '~').
fn write_printable_text(bytes: &[u8], out: &mut dyn Write) -> io::Result<()> {
    // 94 printable ASCII characters: '!' (33) through '~' (126)
    for &b in bytes {
        let ch = (b % 94) + 33;
        out.write_all(&[ch])?;
    }
    writeln!(out)?;
    Ok(())
}

/// Writes bytes in traditional uuencode format.
/// Format: "begin 644 data\n" + encoded lines + "`\nend\n"
fn write_uuencode(bytes: &[u8], out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "begin 644 data")?;

    for chunk in bytes.chunks(45) {
        // Length character
        let len_char = (chunk.len() as u8) + 32;
        out.write_all(&[len_char])?;

        // Encode 3 bytes at a time into 4 characters
        for triple in chunk.chunks(3) {
            // Zero-pad the final triple if fewer than 3 bytes remain.
            // This is standard uuencode behavior: trailing encoded
            // characters represent zero-filled padding bytes.
            let mut buf = [0u8; 3];
            for (i, &b) in triple.iter().enumerate() {
                buf[i] = b;
            }

            let c0 = (buf[0] >> 2) + 32;
            let c1 = (((buf[0] & 0x03) << 4) | (buf[1] >> 4)) + 32;
            let c2 = (((buf[1] & 0x0F) << 2) | (buf[2] >> 6)) + 32;
            let c3 = (buf[2] & 0x3F) + 32;

            out.write_all(&[c0, c1, c2, c3])?;
        }

        writeln!(out)?;
    }

    // End marker: backtick (empty line = length 0 + 32 = 32 = space, but traditional uses '`' = 96)
    writeln!(out, "`")?;
    writeln!(out, "end")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format_to_string(bytes: &[u8], fmt: &OutputFormat) -> String {
        let mut buf = Vec::new();
        format_output(bytes, fmt, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn test_hex() {
        let out = format_to_string(&[0xde, 0xad, 0xbe, 0xef], &OutputFormat::Hex);
        assert_eq!(out, "deadbeef\n");
    }

    #[test]
    fn test_hex_upper() {
        let out = format_to_string(&[0xde, 0xad, 0xbe, 0xef], &OutputFormat::HexUpper);
        assert_eq!(out, "DEADBEEF\n");
    }

    #[test]
    fn test_raw() {
        let data = vec![0x01, 0x02, 0x03];
        let mut buf = Vec::new();
        format_output(&data, &OutputFormat::Raw, &mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_base64() {
        let out = format_to_string(&[0x00, 0x01, 0x02], &OutputFormat::Base64);
        assert_eq!(out, "AAEC\n");
    }

    #[test]
    fn test_base64url() {
        // Bytes that produce '+' and '/' in standard base64
        let out = format_to_string(&[0xfb, 0xff, 0xfe], &OutputFormat::Base64url);
        // base64url should not contain + or /
        assert!(!out.contains('+'));
        assert!(!out.contains('/'));
        assert!(out.trim().len() > 0);
    }

    #[test]
    fn test_octal() {
        let out = format_to_string(&[0o377, 0o001], &OutputFormat::Octal);
        assert_eq!(out, "377 001\n");
    }

    #[test]
    fn test_binary() {
        let out = format_to_string(&[0b10101010, 0b00001111], &OutputFormat::Binary);
        assert_eq!(out, "10101010 00001111\n");
    }

    #[test]
    fn test_text() {
        let out = format_to_string(&[0, 93, 94], &OutputFormat::Text);
        // Each byte maps to (b % 94) + 33
        // 0 → 33 = '!', 93 → 126 = '~', 94 → 33 = '!'
        assert_eq!(out, "!~!\n");
    }

    #[test]
    fn test_uuencode() {
        let out = format_to_string(&[0x43, 0x61, 0x74], &OutputFormat::Uuencode);
        assert!(out.starts_with("begin 644 data\n"));
        assert!(out.ends_with("`\nend\n"));
    }

    #[test]
    fn test_write_output_to_file_hex() {
        let path = std::env::temp_dir().join("mixrand_test_hex_output.txt");
        write_output(&[0xde, 0xad], &OutputFormat::Hex, Some(&path)).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "dead\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_output_to_file_raw() {
        let path = std::env::temp_dir().join("mixrand_test_raw_output.bin");
        write_output(&[0x01, 0x02, 0x03], &OutputFormat::Raw, Some(&path)).unwrap();
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, [0x01, 0x02, 0x03]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_format_output_empty_bytes() {
        let hex = format_to_string(&[], &OutputFormat::Hex);
        assert_eq!(hex, "\n");

        let mut raw_buf = Vec::new();
        format_output(&[], &OutputFormat::Raw, &mut raw_buf).unwrap();
        assert!(raw_buf.is_empty());

        let b64 = format_to_string(&[], &OutputFormat::Base64);
        assert_eq!(b64, "\n");
    }

    #[test]
    fn test_uuencode_full_line() {
        let data: Vec<u8> = (0u8..45).collect();
        let out = format_to_string(&data, &OutputFormat::Uuencode);
        assert!(out.starts_with("begin 644 data\n"));
        assert!(out.ends_with("`\nend\n"));
        let lines: Vec<&str> = out.lines().collect();
        // Second line (index 1) is the encoded data line; length char = 45 + 32 = 77 = 'M'
        assert!(lines[1].starts_with('M'));
    }
}
