# MSS_ADVANCE Revenge

## Challenge Description
Last time we went easy on you. You'll never get the flag this time! `chall.py` `output.txt`

## Vulnerability
We are given two files, `chall.py` and `output.txt`. Inside `output.txt` we have a 1024-bit prime `p`, 20 pairs `(x, y)` where `y = P(x) mod p`, and an AES-CBC encrypted flag.

We can read the source and find this code snippet:
```python
MASTER_KEY = hashlib.sha256(flag).digest()
coeffs = [bytes_to_long(MASTER_KEY)]
for i in range(29):
    co = hashlib.sha256(long_to_bytes(coeffs[-1])).digest()
    coeffs.append(bytes_to_long(co))
```

Every coefficient is a SHA256 digest (exactly 256 bits). The prime `p` is 1024 bits. This is a 4x size gap. This gap is the vulnerability.

## The Attack: LLL Lattice Reduction
After giving all of the information to Claude (Sonnet 4.6) he constructed a 51×51 integer matrix (20 pairs + 30 coefficients + 1 tag row) encoding the constraint `A·c ≡ y (mod p)`. He then crafted a solution script:
```
from fpylll import IntegerMatrix, LLL
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

n_coeffs, n_pairs = 30, 20
dim = n_pairs + n_coeffs + 1  # 51

A_rows, y_vals = [], []
for (x, y_val) in pairs:
    A_rows.append([pow(x, n_coeffs - 1 - i, p) for i in range(n_coeffs)])
    y_vals.append(y_val)

M = IntegerMatrix(dim, dim)
for i in range(n_pairs):
    M[i, i] = p
for i in range(n_coeffs):
    for j in range(n_pairs):
        M[n_pairs + i, j] = A_rows[j][i]
    M[n_pairs + i, n_pairs + i] = 1
for j in range(n_pairs):
    M[dim - 1, j] = -y_vals[j]
M[dim - 1, dim - 1] = 1

LLL.reduction(M)

for row_idx in range(dim):
    row = [M[row_idx, j] for j in range(dim)]
    if abs(row[-1]) != 1:
        continue
    sign = row[-1]
    c_cand = [sign * row[n_pairs + i] for i in range(n_coeffs)]
    master_key_bytes = int(c_cand[0]).to_bytes(32, 'big')
    iv = bytes.fromhex(enc_flag[0])
    ct = bytes.fromhex(enc_flag[1])
    try:
        flag = unpad(AES.new(master_key_bytes, AES.MODE_CBC, iv).decrypt(ct), 16)
        if flag.startswith(b'picoCTF{'):
            print(flag.decode())
            break
    except Exception:
        continue
```

This script outputs the flag `picoCTF{redacted}`.
