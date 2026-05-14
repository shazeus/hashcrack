import re
from typing import Optional

HASH_PATTERNS = [
    {
        "name": "MD5",
        "regex": r"^[a-f0-9]{32}$",
        "length": 32,
        "description": "Message Digest 5",
        "example": "5d41402abc4b2a76b9719d911017c592",
    },
    {
        "name": "SHA-1",
        "regex": r"^[a-f0-9]{40}$",
        "length": 40,
        "description": "Secure Hash Algorithm 1",
        "example": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    },
    {
        "name": "SHA-224",
        "regex": r"^[a-f0-9]{56}$",
        "length": 56,
        "description": "Secure Hash Algorithm 224",
        "example": "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
    },
    {
        "name": "SHA-256",
        "regex": r"^[a-f0-9]{64}$",
        "length": 64,
        "description": "Secure Hash Algorithm 256",
        "example": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    },
    {
        "name": "SHA-384",
        "regex": r"^[a-f0-9]{96}$",
        "length": 96,
        "description": "Secure Hash Algorithm 384",
        "example": "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f",
    },
    {
        "name": "SHA-512",
        "regex": r"^[a-f0-9]{128}$",
        "length": 128,
        "description": "Secure Hash Algorithm 512",
        "example": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    },
    {
        "name": "SHA3-256",
        "regex": r"^[a-f0-9]{64}$",
        "length": 64,
        "description": "SHA3 256-bit (Keccak)",
        "example": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    },
    {
        "name": "SHA3-512",
        "regex": r"^[a-f0-9]{128}$",
        "length": 128,
        "description": "SHA3 512-bit (Keccak)",
        "example": "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
    },
    {
        "name": "NTLM",
        "regex": r"^[a-f0-9]{32}$",
        "length": 32,
        "description": "NT LAN Manager hash (Windows auth)",
        "example": "b4b9b02e6f09a9bd760f388b67351e2b",
    },
    {
        "name": "MySQL4/5",
        "regex": r"^\*[a-f0-9]{40}$",
        "length": 41,
        "description": "MySQL 4.1+ password hash",
        "example": "*900ADE9CA5AE4B40B0E6A8D4E1FEC32DFEA38E4E",
    },
    {
        "name": "bcrypt",
        "regex": r"^\$2[ayb]\$.{56}$",
        "length": None,
        "description": "bcrypt password hash",
        "example": "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
    },
    {
        "name": "Argon2",
        "regex": r"^\$argon2(i|d|id)\$",
        "length": None,
        "description": "Argon2 password hash",
        "example": "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
    },
    {
        "name": "scrypt",
        "regex": r"^\$scrypt\$",
        "length": None,
        "description": "scrypt password hash",
        "example": "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E",
    },
    {
        "name": "MD5 Crypt",
        "regex": r"^\$1\$.{8}\$.{22}$",
        "length": None,
        "description": "MD5 Unix Crypt",
        "example": "$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/",
    },
    {
        "name": "SHA-512 Crypt",
        "regex": r"^\$6\$.{8,16}\$.{86}$",
        "length": None,
        "description": "SHA-512 Unix Crypt",
        "example": "$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/",
    },
    {
        "name": "BLAKE2b",
        "regex": r"^[a-f0-9]{128}$",
        "length": 128,
        "description": "BLAKE2b 512-bit",
        "example": "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    },
    {
        "name": "BLAKE2s",
        "regex": r"^[a-f0-9]{64}$",
        "length": 64,
        "description": "BLAKE2s 256-bit",
        "example": "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812",
    },
    {
        "name": "CRC32",
        "regex": r"^[a-f0-9]{8}$",
        "length": 8,
        "description": "CRC32 cyclic redundancy check",
        "example": "fc4f1d7f",
    },
    {
        "name": "Adler32",
        "regex": r"^[a-f0-9]{8}$",
        "length": 8,
        "description": "Adler-32 checksum",
        "example": "03da018b",
    },
    {
        "name": "RIPEMD-160",
        "regex": r"^[a-f0-9]{40}$",
        "length": 40,
        "description": "RACE Integrity Primitives Evaluation MD 160-bit",
        "example": "108f07b8382412612c048d07d13f814118445acd",
    },
    {
        "name": "Whirlpool",
        "regex": r"^[a-f0-9]{128}$",
        "length": 128,
        "description": "Whirlpool 512-bit hash",
        "example": "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
    },
    {
        "name": "LM Hash",
        "regex": r"^[a-f0-9]{32}$",
        "length": 32,
        "description": "LAN Manager Hash (Windows legacy)",
        "example": "e52cac67419a9a224a3b108f3fa6cb6d",
    },
    {
        "name": "Tiger-192",
        "regex": r"^[a-f0-9]{48}$",
        "length": 48,
        "description": "Tiger 192-bit",
        "example": "9f00f599072300dd276abb38c8eb6dcae6f0f3b0ff6d0f29",
    },
    {
        "name": "Haval-256",
        "regex": r"^[a-f0-9]{64}$",
        "length": 64,
        "description": "Haval 256-bit",
        "example": "4a665e3f9f31e52f42b08cde57a93b2cedc1b8a25a0a76a2a15abd76f5e0a48",
    },
    {
        "name": "Base64",
        "regex": r"^[A-Za-z0-9+/]+=*$",
        "length": None,
        "description": "Base64 encoded string",
        "example": "aGVsbG8gd29ybGQ=",
    },
]

LENGTH_MAP = {
    8: ["CRC32", "Adler32"],
    32: ["MD5", "NTLM", "LM Hash"],
    40: ["SHA-1", "RIPEMD-160"],
    48: ["Tiger-192"],
    56: ["SHA-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s", "Haval-256"],
    96: ["SHA-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"],
}


def detect_hash(hash_string: str) -> list[dict]:
    """Return list of possible hash types for a given hash string."""
    hash_string = hash_string.strip()
    matches = []

    for pattern in HASH_PATTERNS:
        if re.match(pattern["regex"], hash_string, re.IGNORECASE):
            matches.append(pattern)

    # Deduplicate by name
    seen = set()
    unique = []
    for m in matches:
        if m["name"] not in seen:
            seen.add(m["name"])
            unique.append(m)

    return unique


def is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def classify_by_length(length: int) -> list[str]:
    return LENGTH_MAP.get(length, [])
