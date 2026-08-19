from __future__ import annotations

import argparse
import codecs
import encodings.aliases
import json
import os
import sys

# Human-readable description shown by --help. Kept as an explicit constant
# (not __doc__) because `from __future__ import annotations` occupies line 1,
# which prevents a module docstring from becoming __doc__ on Python 3.9.
_DESCRIPTION = """\
Charset_Probe — detect and convert text-file encodings.

Subcommands:
  detect FILE   Detect the encoding of a text file (BOM + byte heuristics).
  list          List the encodings the tool can detect and convert.
  convert FILE  Convert a file between encodings (--from ENC --to ENC).

Examples:
  python3 Charset_Probe.py detect sample.txt
  python3 Charset_Probe.py detect sample.txt --format json
  python3 Charset_Probe.py convert sample.txt --from latin-1 --to utf-8 --output out.txt
"""

# The encodings `detect` can report, with a short description for `list`.
_DETECTABLE = [
    ("ascii", "7-bit ASCII (every byte < 0x80)"),
    ("utf-8", "UTF-8 (BOM, or validated multi-byte sequences)"),
    ("utf-16-le", "UTF-16 little-endian (BOM, or null-byte pattern)"),
    ("utf-16-be", "UTF-16 big-endian (BOM, or null-byte pattern)"),
    ("utf-32-le", "UTF-32 little-endian (BOM FF FE 00 00)"),
    ("utf-32-be", "UTF-32 big-endian (BOM 00 00 FE FF)"),
    ("latin-1", "ISO-8859-1 / Latin-1 (single-byte, high bytes 0xA0-0xFF)"),
    ("windows-1252", "Windows-1252 / CP1252 (single-byte, 0x80-0x9F printable)"),
    ("binary/unknown", "no valid text encoding could be detected"),
]


def _is_valid_utf8(data: bytes) -> bool:
    """Strictly validate UTF-8: rejects overlong forms, surrogates, and >U+10FFFF."""
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b < 0x80:  # ASCII byte — always valid on its own.
            i += 1
            continue
        if b < 0xC0:  # A bare continuation byte can never start a sequence.
            return False
        if b < 0xE0:  # 2-byte sequence: C2..DF 80..BF (C0/C1 are overlong).
            if i + 1 >= n or not (0x80 <= data[i + 1] < 0xC0):
                return False
            if b < 0xC2:
                return False
            i += 2
            continue
        if b < 0xF0:  # 3-byte sequence, rejecting overlong E0 and surrogates ED.
            if i + 2 >= n:
                return False
            b1, b2 = data[i + 1], data[i + 2]
            if not (0x80 <= b1 < 0xC0 and 0x80 <= b2 < 0xC0):
                return False
            if b == 0xE0 and b1 < 0xA0:
                return False
            if b == 0xED and b1 >= 0xA0:
                return False
            i += 3
            continue
        if b < 0xF5:  # 4-byte sequence, rejecting overlong F0 and >U+10FFFF F4.
            if i + 3 >= n:
                return False
            b1, b2, b3 = data[i + 1], data[i + 2], data[i + 3]
            if not (0x80 <= b1 < 0xC0 and 0x80 <= b2 < 0xC0 and 0x80 <= b3 < 0xC0):
                return False
            if b == 0xF0 and b1 < 0x90:
                return False
            if b == 0xF4 and b1 >= 0x90:
                return False
            i += 4
            continue
        return False  # b >= 0xF5 is outside valid UTF-8 range.
    return True


def _detect_utf16_nobom(data: bytes):
    """Return (encoding, confidence, reason) if the bytes look like BOM-less UTF-16, else None.

    ASCII/BMP text in UTF-16 leaves every other byte as 0x00. Little-endian
    stores the high byte second (odd index), big-endian stores it first
    (even index). A strong parity asymmetry is the no-BOM UTF-16 signature.
    """
    n = len(data)
    if n < 4 or n % 2 != 0:
        return None
    pairs = n // 2
    even_nul = sum(1 for k in range(pairs) if data[2 * k] == 0x00)
    odd_nul = sum(1 for k in range(pairs) if data[2 * k + 1] == 0x00)
    le = odd_nul / pairs   # zeros in the high-byte slot => little-endian.
    be = even_nul / pairs  # zeros in the high-byte slot => big-endian.
    if le >= 0.30 and le > be + 0.25:
        conf = min(0.90, 0.50 + 0.40 * le)
        return "utf-16-le", round(conf, 2), f"null-byte pattern ({le:.0%} nulls, no BOM)"
    if be >= 0.30 and be > le + 0.25:
        conf = min(0.90, 0.50 + 0.40 * be)
        return "utf-16-be", round(conf, 2), f"null-byte pattern ({be:.0%} nulls, no BOM)"
    return None


def _single_byte_guess(data: bytes, n: int, high: int, c0: int):
    """Classify NUL-free, non-UTF-8 high-byte data as Latin-1, Windows-1252, or binary."""
    # A dense run of C0 control bytes (other than TAB/LF/CR) => not meaningful text.
    if c0 / n > 0.05:
        return "binary/unknown", 0.00, "binary data (control bytes, no valid text encoding)"

    high_ratio = high / n
    # Bytes 0x80-0x9F are C1 controls in Latin-1 but printable in CP1252,
    # so their presence strongly favors Windows-1252.
    c1 = sum(1 for b in data if 0x80 <= b <= 0x9F)
    if c1 > 0:
        return "windows-1252", 0.80, f"{high_ratio:.0%} high bytes incl. 0x80-0x9F range"
    return "latin-1", 0.60, f"{high_ratio:.0%} high bytes, only 0xA0-0xFF range"


def _detect_encoding(data: bytes):
    """Return (encoding, confidence, reason) for the raw bytes of a file."""
    # 1) Byte-order-mark sniffing. Longer UTF-32 BOMs must be checked before
    #    the shorter UTF-16 BOMs they start with.
    if data.startswith(b"\xff\xfe\x00\x00"):
        return "utf-32-le", 1.00, "BOM FF FE 00 00"
    if data.startswith(b"\x00\x00\xfe\xff"):
        return "utf-32-be", 1.00, "BOM 00 00 FE FF"
    if data.startswith(b"\xff\xfe"):
        return "utf-16-le", 1.00, "BOM FF FE"
    if data.startswith(b"\xfe\xff"):
        return "utf-16-be", 1.00, "BOM FE FF"
    if data.startswith(b"\xef\xbb\xbf"):
        return "utf-8", 1.00, "BOM EF BB BF"

    # 2) Empty input is trivially ASCII.
    if not data:
        return "ascii", 1.00, "empty file (0 bytes)"

    # 3) BOM-less UTF-16 must be checked BEFORE the ASCII/UTF-8 tests: ASCII text
    #    stored as UTF-16 is byte-for-byte indistinguishable from ASCII unless
    #    you notice the interleaved 0x00 bytes (which are also < 0x80).
    u16 = _detect_utf16_nobom(data)
    if u16 is not None:
        return u16

    n = len(data)
    nul = data.count(0x00)
    high = sum(1 for b in data if b >= 0x80)
    # C0 control bytes other than TAB/LF/CR (whitespace stays valid in text).
    c0 = sum(1 for b in data if b < 0x20 and b not in (0x09, 0x0A, 0x0D))

    # 4) NUL bytes never appear in meaningful single-byte text (ASCII/UTF-8/
    #    Latin-1/Windows-1252) — they signal binary content.
    if nul > 0:
        return "binary/unknown", 0.00, "binary data (NUL bytes, no valid text encoding)"

    # 5) Pure ASCII: no high bytes and no NULs.
    if high == 0:
        if c0 / n > 0.05:
            return "binary/unknown", 0.00, "binary data (control bytes, no valid text encoding)"
        return "ascii", 1.00, "all bytes are 7-bit ASCII"

    # 6) Valid UTF-8 with multi-byte sequences (strict validation, no BOM).
    if _is_valid_utf8(data):
        return "utf-8", 0.98, "valid UTF-8 multi-byte sequences (no BOM)"

    # 7) NUL-free, non-UTF-8 high-byte data — guess among single-byte encodings.
    return _single_byte_guess(data, n, high, c0)


def cmd_detect(args):
    """Detect the encoding of a file and report it with a confidence score."""
    path = args.file
    # Missing/invalid file => stderr + nonzero exit (CI-friendly failure).
    if not os.path.exists(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    if os.path.isdir(path):
        print(f"Error: '{path}' is a directory, not a file", file=sys.stderr)
        return 1
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"Error: cannot read '{path}': {e}", file=sys.stderr)
        return 1

    encoding, confidence, reason = _detect_encoding(data)
    result = {
        "file": path,
        "encoding": encoding,
        "confidence": confidence,
        "reason": reason,
        "size": len(data),
    }
    if args.format == "json":
        print(json.dumps(result))
    else:
        print(f"file: {path}")
        print(f"encoding: {encoding}")
        print(f"confidence: {confidence:.2f}")
        print(f"reason: {reason}")
        print(f"size: {len(data)} bytes")
    return 0


def cmd_list(args):
    """List the encodings the tool can detect and convert."""
    if args.format == "json":
        payload = {
            "detectable": [{"name": n, "description": d} for n, d in _DETECTABLE],
            "convert": "any codec in Python's codec registry (via codecs.lookup)",
        }
        print(json.dumps(payload))
    else:
        print("Detectable encodings:")
        for name, desc in _DETECTABLE:
            print(f"  {name:<16} {desc}")
        print()
        print("Convert: --from/--to accept any codec in Python's codec registry")
        print("  (e.g. utf-8, utf-8-sig, utf-16, utf-16-le, utf-32, ascii,")
        print("   latin-1 / iso-8859-1, windows-1252 / cp1252, iso-8859-15, cp437)")
    return 0


def _print_codec_hint():
    """Print supported-codec information after an unknown-encoding error."""
    common = [
        "ascii", "utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be",
        "utf-32", "utf-32-le", "utf-32-be", "latin-1", "iso-8859-1",
        "iso-8859-15", "windows-1252", "cp1252", "cp437", "mac-roman",
    ]
    print("Supported codecs include: " + ", ".join(common), file=sys.stderr)
    try:
        canon = sorted(set(encodings.aliases.aliases.values()))
    except Exception:
        canon = []
    if canon:
        print("Full registry: " + ", ".join(canon), file=sys.stderr)
    print("Run 'list' to see the encodings this tool can detect.", file=sys.stderr)


def cmd_convert(args):
    """Convert a file from one encoding to another (stdout unless --output)."""
    path = args.file
    # Missing/invalid file => stderr + nonzero exit.
    if not os.path.exists(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    if os.path.isdir(path):
        print(f"Error: '{path}' is a directory, not a file", file=sys.stderr)
        return 1
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"Error: cannot read '{path}': {e}", file=sys.stderr)
        return 1

    # Validate both encoding names via codecs.lookup (raises LookupError on unknown).
    try:
        from_codec = codecs.lookup(args.from_enc)
        to_codec = codecs.lookup(args.to_enc)
    except LookupError as e:
        print(f"Error: unknown encoding: {e}", file=sys.stderr)
        _print_codec_hint()
        return 1

    # Decode the raw bytes using the source encoding (strict => binary fails loudly).
    try:
        text = data.decode(from_codec.name)
    except (UnicodeDecodeError, ValueError) as e:
        print(f"Error: cannot decode input as '{args.from_enc}': {e}", file=sys.stderr)
        return 1

    # Re-encode to the target encoding.
    try:
        out_bytes = text.encode(to_codec.name)
    except (UnicodeEncodeError, ValueError) as e:
        print(f"Error: cannot encode text as '{args.to_enc}': {e}", file=sys.stderr)
        return 1

    if args.output:
        # Create parent directories so `-o path/to/new/file.txt` just works.
        out_path = args.output
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        try:
            with open(out_path, "wb") as f:
                f.write(out_bytes)
        except OSError as e:
            print(f"Error: cannot write '{out_path}': {e}", file=sys.stderr)
            return 1
        if args.format == "json":
            print(json.dumps({
                "written": True,
                "output": out_path,
                "bytes": len(out_bytes),
                "from": from_codec.name,
                "to": to_codec.name,
            }))
        else:
            print(f"Wrote {len(out_bytes)} bytes to {out_path} ({from_codec.name} -> {to_codec.name})")
    else:
        # No --output: write the converted bytes directly to stdout (binary-safe),
        # so output can be piped or redirected like `> out.txt`.
        sys.stdout.buffer.write(out_bytes)
        sys.stdout.buffer.flush()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with a shared --format flag on every subcommand."""
    # Shared parent: --format works both before AND after the subcommand.
    # default=SUPPRESS means the attribute is only set when the flag is passed,
    # so the top-level value (or the text fallback) is never clobbered.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json"],
                        default=argparse.SUPPRESS,
                        help="Output format (default: text)")

    p = argparse.ArgumentParser(
        prog="Charset_Probe",
        description=_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
    )
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("detect", parents=[common],
                       help="Detect the encoding of a file")
    d.add_argument("file", help="Path to the file to detect")
    d.set_defaults(func=cmd_detect)

    l = sub.add_parser("list", parents=[common],
                       help="List detectable/convertible encodings")
    l.set_defaults(func=cmd_list)

    c = sub.add_parser("convert", parents=[common],
                       help="Convert a file between encodings")
    c.add_argument("file", help="Path to the file to convert")
    c.add_argument("--from", dest="from_enc", required=True, metavar="ENC",
                   help="Source encoding (e.g. latin-1, utf-16, cp1252)")
    c.add_argument("--to", dest="to_enc", required=True, metavar="ENC",
                   help="Target encoding (e.g. utf-8, utf-16-le)")
    c.add_argument("--output", "-o", default=None,
                   help="Output file (default: write to stdout)")
    c.set_defaults(func=cmd_convert)

    return p


def main(argv=None) -> int:
    """Parse arguments once, resolve the --format fallback, and dispatch."""
    args = build_parser().parse_args(argv)
    # Resolve the fallback here: SUPPRESS leaves the attribute unset when the
    # flag was not provided in any position, so default to "text".
    args.format = getattr(args, "format", "text") or "text"
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
