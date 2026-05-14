<p align="center">
  <h1 align="center">hashcrack</h1>
  <p align="center">Hash identification and lookup tool for CTF and security research.</p>
  <p align="center">
    <a href="https://pypi.org/project/hashcrack-cli/"><img src="https://img.shields.io/pypi/v/hashcrack-cli?color=blue&style=flat-square" alt="PyPI"></a>
    <a href="https://pypi.org/project/hashcrack-cli/"><img src="https://img.shields.io/pypi/pyversions/hashcrack-cli?style=flat-square" alt="Python"></a>
    <a href="https://github.com/shazeus/hashcrack/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
    <a href="https://github.com/shazeus/hashcrack/stargazers"><img src="https://img.shields.io/github/stars/shazeus/hashcrack?style=flat-square" alt="Stars"></a>
  </p>
</p>

---

**hashcrack** is a fast, feature-rich CLI tool for hash analysis in CTF competitions and security research. It auto-detects hash types (MD5, SHA-1, SHA-256, bcrypt, NTLM, and 20+ more), queries public hash databases, performs wordlist attacks, generates hashes, and provides deep statistical analysis — all with beautiful terminal output powered by Rich.

- **Auto-detection** — identifies 20+ hash types from MD5 to Argon2, bcrypt, NTLM, and scrypt
- **Online lookup** — queries multiple public hash cracking APIs simultaneously
- **Wordlist attack** — crack hashes locally using any wordlist (e.g. rockyou.txt)
- **Hash generation** — compute MD5, SHA-1, SHA-256, SHA-512, BLAKE2 and more in one command
- **Batch mode** — process hundreds of hashes from a file with optional auto-lookup
- **Verification** — confirm plaintext/hash pairs across all supported algorithms
- **Deep analysis** — entropy calculation, charset analysis, and type classification
- **JSON output** — every command supports `--json` for scripting and piping

## Installation

```bash
pip install hashcrack-cli
```

Or install from source:

```bash
git clone https://github.com/shazeus/hashcrack
cd hashcrack
pip install -e .
```

## Usage

```bash
# Identify a hash type
hashcrack identify 5d41402abc4b2a76b9719d911017c592

# Look up plaintext via public APIs
hashcrack lookup 5d41402abc4b2a76b9719d911017c592

# Generate hashes
hashcrack generate "hello world"
hashcrack generate "secret" --algo md5 --algo sha256

# Crack with a wordlist
hashcrack wordlist rockyou.txt 5d41402abc4b2a76b9719d911017c592

# Batch process hashes from a file
hashcrack batch hashes.txt --lookup

# Verify plaintext against hash
hashcrack verify 5d41402abc4b2a76b9719d911017c592 "hello"

# Deep analysis
hashcrack analyze 5d41402abc4b2a76b9719d911017c592

# List all supported hash types
hashcrack info
```

## Commands

| Command | Description |
|---------|-------------|
| `identify <hash>` | Auto-detect the type(s) of a hash |
| `lookup <hash>` | Query public databases for the plaintext |
| `generate <text>` | Generate hashes for a string (all algorithms or specific ones) |
| `wordlist <file> <hash>` | Crack a hash using a local wordlist |
| `batch <file>` | Process multiple hashes from a file |
| `verify <hash> <plaintext>` | Confirm a hash/plaintext pair |
| `analyze <hash>` | Full analysis: type + lookup + entropy + charset |
| `info [type]` | Show details for a hash type, or list all supported types |

## Configuration

All commands support these global options:

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON for scripting |
| `-q / --quiet` | Minimal output (useful in scripts) |
| `-h / --help` | Show help for any command |
| `-V / --version` | Show version |

## Supported Hash Types

MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, NTLM, LM Hash, bcrypt, Argon2, scrypt, MD5 Crypt, SHA-512 Crypt, RIPEMD-160, BLAKE2b, BLAKE2s, CRC32, Adler32, Tiger-192, Haval-256, MySQL4/5, Whirlpool, Base64

## License

MIT — see [LICENSE](LICENSE).
