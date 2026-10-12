import string
from math import gcd

ALPHA = string.ascii_uppercase


def caesar(text, n, direction="right"):
    shift = n % 26
    if direction == "left":
        shift = -shift
    out = []
    for ch in text:
        if ch.isascii() and ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def caesar_decrypt(text, n, direction="right"):
    other = "left" if direction == "right" else "right"
    return caesar(text, n, other)


def caesar_bruteforce(text):
    return [(k, caesar(text, k, "left")) for k in range(26)]


FREQ_EN = "ETAOINSHRDLU"


def caesar_frequency_guess(text):
    letters = [c for c in text.upper() if c in ALPHA]
    if not letters:
        return 0
    counts = {c: letters.count(c) for c in ALPHA}
    top = max(counts, key=counts.get)
    return (ALPHA.index(top) - ALPHA.index("E")) % 26


def clean(text):
    return "".join(c for c in text.upper() if c in ALPHA)


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def inv_mod(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m


def det(m):
    n = len(m)
    if n == 1:
        return m[0][0]
    if n == 2:
        return m[0][0] * m[1][1] - m[0][1] * m[1][0]
    total = 0
    for j in range(n):
        minor = [row[:j] + row[j + 1:] for row in m[1:]]
        total += ((-1) ** j) * m[0][j] * det(minor)
    return total


def mat_inverse_mod(m, mod=26):
    n = len(m)
    d = det(m) % mod
    if gcd(d, mod) != 1:
        raise ValueError("key matrix is not invertible mod 26")
    di = inv_mod(d, mod)
    if n == 1:
        return [[di]]
    cof = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = [r[:j] + r[j + 1:] for k, r in enumerate(m) if k != i]
            cof[i][j] = ((-1) ** (i + j)) * det(minor)
    return [[(cof[j][i] * di) % mod for j in range(n)] for i in range(n)]


def key_from_text(word):
    letters = clean(word)
    size = int(len(letters) ** 0.5)
    if size < 2 or size * size != len(letters):
        raise ValueError("key must have 4 or 9 letters")
    nums = [ALPHA.index(c) for c in letters]
    return [nums[i * size:(i + 1) * size] for i in range(size)]


def hill_encrypt(text, key):
    n = len(key)
    det_ok = gcd(det(key) % 26, 26) == 1
    if not det_ok:
        raise ValueError("key matrix is not invertible mod 26")
    letters = clean(text)
    while len(letters) % n:
        letters += "X"
    out = []
    for i in range(0, len(letters), n):
        block = [ALPHA.index(c) for c in letters[i:i + n]]
        for r in range(n):
            out.append(ALPHA[sum(key[r][c] * block[c] for c in range(n)) % 26])
    return "".join(out)


def hill_decrypt(text, key):
    inv = mat_inverse_mod(key)
    n = len(key)
    letters = clean(text)
    if len(letters) % n:
        raise ValueError("ciphertext length must be a multiple of %d" % n)
    out = []
    for i in range(0, len(letters), n):
        block = [ALPHA.index(c) for c in letters[i:i + n]]
        for r in range(n):
            out.append(ALPHA[sum(inv[r][c] * block[c] for c in range(n)) % 26])
    return "".join(out)


def hill_known_plaintext(plain, cipher, n=2):
    p = [ALPHA.index(c) for c in clean(plain)]
    c = [ALPHA.index(x) for x in clean(cipher)]
    if len(p) < n * n or len(c) < n * n:
        raise ValueError("need at least n*n letters")
    for start in range(0, len(p) - n * n * 1 + 1, n):
        P = [[p[start + i * n + j] for i in range(n)] for j in range(n)]
        C = [[c[start + i * n + j] for i in range(n)] for j in range(n)]
        try:
            Pinv = mat_inverse_mod(P)
        except ValueError:
            continue
        K = [[sum(C[r][k] * Pinv[k][col] for k in range(n)) % 26 for col in range(n)] for r in range(n)]
        return K
    raise ValueError("no invertible plaintext block found")


def playfair_square(key):
    seen = []
    for ch in clean(key).replace("J", "I") + ALPHA.replace("J", ""):
        if ch not in seen:
            seen.append(ch)
    return seen


def playfair_pairs(text):
    letters = clean(text).replace("J", "I")
    pairs = []
    i = 0
    while i < len(letters):
        a = letters[i]
        if i + 1 < len(letters):
            b = letters[i + 1]
            if a == b:
                pairs.append((a, "X"))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        else:
            pairs.append((a, "X"))
            i += 1
    return pairs


def playfair_step(pairs, square, step):
    out = []
    for a, b in pairs:
        ia, ib = square.index(a), square.index(b)
        ra, ca = divmod(ia, 5)
        rb, cb = divmod(ib, 5)
        if ra == rb:
            out.append(square[ra * 5 + (ca + step) % 5] + square[rb * 5 + (cb + step) % 5])
        elif ca == cb:
            out.append(square[((ra + step) % 5) * 5 + ca] + square[((rb + step) % 5) * 5 + cb])
        else:
            out.append(square[ra * 5 + cb] + square[rb * 5 + ca])
    return "".join(out)


def playfair_encrypt(text, key):
    sq = playfair_square(key)
    return playfair_step(playfair_pairs(text), sq, 1)


def playfair_decrypt(text, key):
    sq = playfair_square(key)
    letters = clean(text).replace("J", "I")
    if len(letters) % 2:
        raise ValueError("ciphertext length must be even")
    pairs = [(letters[i], letters[i + 1]) for i in range(0, len(letters), 2)]
    return playfair_step(pairs, sq, -1)


def playfair_strip_padding(text):
    out = []
    i = 0
    while i < len(text):
        if text[i] == "X" and 0 < i < len(text) - 1 and text[i - 1] == text[i + 1]:
            i += 1
            continue
        out.append(text[i])
        i += 1
    if out and out[-1] == "X":
        out.pop()
    return "".join(out)


def digram_counts(text):
    letters = clean(text)
    counts = {}
    for i in range(0, len(letters) - 1, 2):
        d = letters[i:i + 2]
        counts[d] = counts.get(d, 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])
