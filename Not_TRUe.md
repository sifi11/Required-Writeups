# Not TRUe

## Approach

The challenge name "Not TRUe" hints at truncation. In cryptographic implementations, MACs and hashes use their full output length. However, when the output is truncated to a small number of bits, it becomes computationally trivial to forge a valid tag through brute force.

### Vulnerability

1. **Truncated MAC/Hash**: The server computes a MAC or hash over user-supplied data but only checks a truncated portion. This drastically reduces the search space from 2^256 to 2^16 or 2^32.

2. **Birthday-style collision**: With a 16-bit truncation, we only need about 2^8 = 256 attempts on average or at most 2^16 = 65536 attempts for a guaranteed match.

## Solution

1. Connect to the challenge server using netcat or pwntools
2. Analyze the server's response to understand the expected format
3. Brute-force the truncated hash/MAC by iterating through possible values
4. Send the forged message
5. Retreive the flag

## Script
We told to Claude to make a script to brute force it with the information we had gathered. It returned this.
```

from pwn import *
import hashlib
import hmac
import itertools
import sys

HOST = "HOST"   # replace with actual host
PORT = port                     # replace with actual port

context.log_level = "info"

def connect():
    return remote(HOST, PORT)


def recv_until_prompt(io: tube) -> str:

    try:
        data = io.recvrepeat(timeout=2)
    except EOFError:
        data = b""
    return data.decode(errors="replace")

def truncated_sha256(data: bytes, trunc_bytes: int) -> bytes:
    return hashlib.sha256(data).digest()[:trunc_bytes]

def truncated_md5(data: bytes, trunc_bytes: int) -> bytes:
    return hashlib.md5(data).digest()[:trunc_bytes]

def truncated_hmac_sha256(key: bytes, data: bytes, trunc_bytes: int) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()[:trunc_bytes]

def bruteforce_truncated_hash(target_hex: str, prefix: bytes = b"") -> bytes | None:
    target = bytes.fromhex(target_hex)
    trunc  = len(target)
    bits   = trunc * 8

    log.info(f"Target  : {target_hex}  ({bits}-bit truncation)")
    log.info(f"Max iter: {2**bits:,}")

    for i in itertools.count(0):
        candidate = prefix + str(i).encode()
        if truncated_sha256(candidate, trunc) == target:
            log.success(f"Found after {i+1} tries: {candidate!r}")
            return candidate

        if i > 2**bits:
            log.error("Exhausted search space without a match.")
            return None


def bruteforce_token(target_hex: str) -> str:
    target = bytes.fromhex(target_hex)
    trunc  = len(target)
    for i in range(2 ** (trunc * 8)):
        guess = i.to_bytes(trunc, "big")
        if guess == target:
            return guess.hex()
    return ""

def solve():
    io = connect()
    banner = recv_until_prompt(io)
    log.info("Server says:\n" + banner)


    import re

    mac_match = re.search(
        r"(?:mac|hash|tag|checksum|token)[^\n:]*[:\s]+([0-9a-fA-F]{4,16})",
        banner, re.IGNORECASE
    )
    msg_match = re.search(
        r"(?:message|msg|data)[^\n:]*[:\s]+(.+)",
        banner, re.IGNORECASE
    )

    if mac_match:
        target_hex = mac_match.group(1).strip().lower()
        prefix     = msg_match.group(1).strip().encode() if msg_match else b""
        log.info(f"Pattern A — target MAC: {target_hex}, prefix: {prefix!r}")
        payload = bruteforce_truncated_hash(target_hex, prefix=prefix)
        if payload is None:
            log.error("Brute force failed.")
            io.close(); return
first, then raw
        io.sendlineafter(b":", payload.hex().encode())

    elif "find" in banner.lower() or "sha256" in banner.lower():
        target_hex = re.search(r"[0-9a-fA-F]{4,16}", banner).group(0).lower()
        log.info(f"Pattern B — PoW target: {target_hex}")
        payload = bruteforce_truncated_hash(target_hex)
        io.sendlineafter(b"=", payload)

    else:
        log.warning("Unknown protocol — entering interactive mode.")
 expects, iterate
        username = b"admin"
        io.sendlineafter(b":", username)

        resp = recv_until_prompt(io)
        log.info("After username:\n" + resp)

        token_target = re.search(r"[0-9a-fA-F]{4,16}", resp)
        if token_target:
            target_hex = token_target.group(0).lower()
            payload    = bruteforce_truncated_hash(target_hex, prefix=username)
            io.sendlineafter(b":", payload.hex().encode())
        else:
            io.interactive()
            return

    result = recv_until_prompt(io)
    log.info("Server response:\n" + result)

    flag = re.search(r"picoCTF\{[^}]+\}", result)
    if flag:
        log.success("FLAG: " + flag.group(0))
    else:
        log.warning("Flag not found in output — dropping to interactive mode.")
        io.interactive()

    io.close()

solve()
```
That led us to get the flag via bruteforcing the file.
