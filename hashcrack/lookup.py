import hashlib
import requests
from typing import Optional

HEADERS = {"User-Agent": "hashcrack/0.1.0 (CTF hash lookup tool)"}
TIMEOUT = 10


def lookup_md5_online(hash_str: str) -> Optional[str]:
    """Try multiple free hash lookup APIs for MD5/SHA1/SHA256."""
    hash_str = hash_str.lower().strip()

    # md5decrypt.net
    try:
        url = f"https://md5decrypt.net/Api/api.php?hash={hash_str}&hash_type=md5&email=test@test.com&code=code1"
        resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        if resp.ok and resp.text and resp.text not in ("", "ACCESS_DENIED", "INVALID_HASH", "NOT_FOUND"):
            return resp.text.strip()
    except Exception:
        pass

    return None


def lookup_nitrxgen(hash_str: str) -> Optional[str]:
    """Use nitrxgen rainbow table lookup for MD5."""
    hash_str = hash_str.lower().strip()
    try:
        url = f"https://www.nitrxgen.net/md5db/{hash_str}"
        resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        if resp.ok and resp.text.strip():
            return resp.text.strip()
    except Exception:
        pass
    return None


def lookup_hashes_com(hash_str: str) -> Optional[str]:
    """Query hashes.com API."""
    hash_str = hash_str.lower().strip()
    try:
        url = f"https://hashes.com/en/api/identify"
        resp = requests.post(
            url,
            data={"hash": hash_str},
            timeout=TIMEOUT,
            headers=HEADERS,
        )
        if resp.ok:
            data = resp.json()
            if data.get("result"):
                return data["result"]
    except Exception:
        pass
    return None


def lookup_hashtoolkit(hash_str: str) -> Optional[str]:
    """Query hashtoolkit.com."""
    hash_str = hash_str.lower().strip()
    try:
        url = f"https://hashtoolkit.com/reverse-hash/?hash={hash_str}"
        resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        if resp.ok:
            import re
            match = re.search(r'<span class="hashValue">(.*?)</span>', resp.text)
            if match:
                return match.group(1).strip()
    except Exception:
        pass
    return None


def crackstation_lookup(hash_str: str) -> Optional[str]:
    """Query CrackStation via their API."""
    hash_str = hash_str.lower().strip()
    try:
        url = "https://crackstation.net/crackstation-api/v1/hash.php"
        resp = requests.post(
            url,
            data={"hash": hash_str, "submit": "Crack Hashes"},
            timeout=TIMEOUT,
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.ok and resp.text:
            import json
            try:
                results = json.loads(resp.text)
                if isinstance(results, list) and results and results[0].get("cracked"):
                    return results[0].get("plaintext")
            except Exception:
                pass
    except Exception:
        pass
    return None


def lookup_hash(hash_str: str, hash_type: Optional[str] = None) -> dict:
    """
    Attempt to look up plaintext for a hash using multiple public services.
    Returns dict with 'found', 'plaintext', 'source' keys.
    """
    hash_str = hash_str.strip()
    result = {"found": False, "plaintext": None, "source": None}

    # Try multiple sources
    sources = [
        ("nitrxgen (MD5 rainbow tables)", lookup_nitrxgen),
        ("hashes.com", lookup_hashes_com),
        ("hashtoolkit.com", lookup_hashtoolkit),
        ("crackstation.net", crackstation_lookup),
    ]

    for source_name, fn in sources:
        try:
            plaintext = fn(hash_str)
            if plaintext:
                result["found"] = True
                result["plaintext"] = plaintext
                result["source"] = source_name
                return result
        except Exception:
            continue

    return result


def generate_hash(text: str, algorithm: str) -> Optional[str]:
    """Generate hash of given text using specified algorithm."""
    algorithm = algorithm.lower().replace("-", "").replace("_", "")
    algo_map = {
        "md5": "md5",
        "sha1": "sha1",
        "sha224": "sha224",
        "sha256": "sha256",
        "sha384": "sha384",
        "sha512": "sha512",
        "sha3224": "sha3_224",
        "sha3256": "sha3_256",
        "sha3384": "sha3_384",
        "sha3512": "sha3_512",
        "blake2b": "blake2b",
        "blake2s": "blake2s",
    }

    algo_key = algo_map.get(algorithm)
    if not algo_key:
        return None

    try:
        h = hashlib.new(algo_key)
        h.update(text.encode("utf-8"))
        return h.hexdigest()
    except ValueError:
        return None


def verify_hash(hash_str: str, plaintext: str, algorithm: str) -> bool:
    """Verify that plaintext matches hash using given algorithm."""
    computed = generate_hash(plaintext, algorithm)
    if computed is None:
        return False
    return computed.lower() == hash_str.lower().strip()
