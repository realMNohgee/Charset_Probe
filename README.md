# Charset_Probe
![CI](https://github.com/realMNohgee/Charset_Probe/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)**

Detect and convert text-file encodings from the command line — BOM sniffing plus
byte-pattern heuristics, with a confidence score, and lossless re-encoding between
any two codecs. Zero dependencies, pure Python standard library.

## One tool, many domains

| Domain | What Charset_Probe does there |
|---|---|
| Data ingestion / ETL | Fingerprint incoming CSV/JSON/text files before parsing so a pipeline never chokes on mojibake |
| Web scraping & crawling | Re-encode legacy `latin-1`/`cp1252` pages into UTF-8 for a uniform corpus |
| Localization / i18n | Distinguish UTF-8 vs UTF-16 vs Windows-1252 source files before translation tooling |
| Forensics & log analysis | Classify unknown byte streams and flag `binary/unknown` content that isn't text |
| Agentic AI plumbing | A deterministic pre-flight check so an agent reads a file with the *correct* codec instead of guessing |

## Why it matters for agentic AI

Autonomous agents routinely read files they did not create. A single mis-detected
encoding turns "café" into "cafÃ©" and silently corrupts every downstream step.
`Charset_Probe` gives agents a machine-readable, confidence-scored answer
(`--format json`) and a clean nonzero exit on failure — so an agent can *decide*
to re-encode or abort instead of propagating garbage.

## Install

No installation needed — it's one file, standard library only (Python 3.7+).

```bash
git clone git@github.com:realMNohgee/Charset_Probe.git
cd Charset_Probe
python3 Charset_Probe.py --help
```

## Quick start

```bash
# Detect the encoding of a file (text output)
python3 Charset_Probe.py detect sample.txt

# Same result as JSON (confidence is a float 0.0-1.0)
python3 Charset_Probe.py detect sample.txt --format json

# List what it can detect and convert
python3 Charset_Probe.py list

# Convert a legacy Latin-1 file to UTF-8
python3 Charset_Probe.py convert legacy.txt --from latin-1 --to utf-8 --output out.txt

# Convert and stream to stdout (no --output)
python3 Charset_Probe.py convert legacy.txt --from latin-1 --to utf-8 > out.txt
```

`--format text|json` works both before and after the subcommand.

## Examples

```text
$ python3 Charset_Probe.py detect sample.txt
file: sample.txt
encoding: utf-8
confidence: 0.98
reason: valid UTF-8 multi-byte sequences (no BOM)
size: 23 bytes
```

```text
$ python3 Charset_Probe.py detect blob.bin --format json
{"file": "blob.bin", "encoding": "binary/unknown", "confidence": 0.0, "reason": "binary data (NUL/control bytes, no valid text encoding)", "size": 4096}
```

## How detection works

1. **BOM first** — UTF-8 `EF BB BF`, UTF-16 LE `FF FE`, UTF-16 BE `FE FF`,
   UTF-32 LE `FF FE 00 00`, UTF-32 BE `00 00 FE FF` (longer BOMs checked first).
2. **Pure ASCII** — every byte below `0x80`.
3. **Valid UTF-8** — strict multi-byte validation (overlong/surrogate/range safe).
4. **Byte-frequency heuristics** — null-byte pattern for UTF-16 without a BOM,
   then high-byte range (`0x80-0x9F` → Windows-1252, `0xA0-0xFF` → Latin-1).
5. **Binary guard** — NUL/control-byte density with no valid text → `binary/unknown`.

## Exit codes

`0` success · `1` missing file, unknown encoding, or undecodable input — with the
error on stderr, so the tool works as a CI gate.

## License

MIT — see [LICENSE](LICENSE).

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)**
