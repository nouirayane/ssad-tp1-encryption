import random
import time
import unittest

import ciphers
import integrity
import passwords


class CaesarTests(unittest.TestCase):
    def test_roundtrip_both_directions(self):
        msg = "Hello, World! xyz"
        for n in range(0, 60):
            for d in ("right", "left"):
                enc = ciphers.caesar(msg, n, d)
                self.assertEqual(ciphers.caesar_decrypt(enc, n, d), msg)

    def test_known_value(self):
        self.assertEqual(ciphers.caesar("ABC xyz", 3, "right"), "DEF abc")
        self.assertEqual(ciphers.caesar("DEF abc", 3, "left"), "ABC xyz")

    def test_bruteforce_contains_plaintext(self):
        enc = ciphers.caesar("attack at dawn", 7)
        self.assertIn("attack at dawn", [t for _, t in ciphers.caesar_bruteforce(enc)])

    def test_frequency_guess(self):
        text = "Be sure to keep the secret between the three of them, never tell the others"
        enc = ciphers.caesar(text, 11)
        self.assertEqual(ciphers.caesar_frequency_guess(enc), 11)


class HillTests(unittest.TestCase):
    def test_classic_example(self):
        key = ciphers.key_from_text("GYBNQKURP")
        self.assertEqual(ciphers.hill_encrypt("ACT", key), "POH")

    def test_roundtrip_2x2(self):
        key = [[3, 3], [2, 5]]
        enc = ciphers.hill_encrypt("HELP", key)
        self.assertEqual(enc, "HIAT")
        self.assertEqual(ciphers.hill_decrypt(enc, key), "HELP")

    def test_roundtrip_random_keys(self):
        rnd = random.Random(4)
        done = 0
        while done < 40:
            n = rnd.choice([2, 3])
            key = [[rnd.randrange(26) for _ in range(n)] for _ in range(n)]
            try:
                ciphers.mat_inverse_mod(key)
            except ValueError:
                continue
            msg = "".join(rnd.choice(ciphers.ALPHA) for _ in range(n * 5))
            self.assertEqual(ciphers.hill_decrypt(ciphers.hill_encrypt(msg, key), key), msg)
            done += 1

    def test_bad_key_rejected(self):
        with self.assertRaises(ValueError):
            ciphers.hill_encrypt("HELLO", [[2, 4], [1, 2]])

    def test_known_plaintext_attack(self):
        key = [[3, 3], [2, 5]]
        plain = "MEETMEATNOON"
        enc = ciphers.hill_encrypt(plain, key)
        self.assertEqual(ciphers.hill_known_plaintext(plain, enc, 2), key)


class PlayfairTests(unittest.TestCase):
    def test_wikipedia_example(self):
        enc = ciphers.playfair_encrypt("hide the gold in the tree stump", "playfair example")
        self.assertEqual(enc, "BMODZBXDNABEKUDMUIXMMOUVIF")

    def test_roundtrip(self):
        enc = ciphers.playfair_encrypt("balloon", "monarchy")
        dec = ciphers.playfair_decrypt(enc, "monarchy")
        self.assertEqual(ciphers.playfair_strip_padding(dec), "BALLOON")

    def test_odd_length(self):
        enc = ciphers.playfair_encrypt("abc", "key")
        self.assertEqual(len(enc) % 2, 0)


class PasswordTests(unittest.TestCase):
    def test_binary_space(self):
        self.assertEqual(passwords.search_space(passwords.BINARY, 3), 8)
        self.assertEqual(passwords.search_space(passwords.DIGITS_1_4, 4), 256)

    def test_bruteforce_finds_all_binary(self):
        import itertools
        for combo in itertools.product("01", repeat=3):
            pw = "".join(combo)
            found, _, _ = passwords.brute_force(passwords.sha(pw), "01", 3)
            self.assertEqual(found, pw)

    def test_bruteforce_digits(self):
        found, tries, _ = passwords.brute_force(passwords.sha("4321"), "1234", 4)
        self.assertEqual(found, "4321")
        self.assertLessEqual(tries, 256)

    def test_dictionary_hit_and_miss(self):
        self.assertEqual(passwords.dictionary_attack(passwords.sha("qwerty"))[0], "qwerty")
        self.assertIsNone(passwords.dictionary_attack(passwords.sha("zzzzzz"))[0])

    def test_pbkdf2_record(self):
        rec = passwords.make_record("S3cret*Pass", 1000)
        self.assertTrue(passwords.check_record(rec, "S3cret*Pass"))
        self.assertFalse(passwords.check_record(rec, "s3cret*Pass"))

    def test_same_password_different_salt(self):
        a = passwords.make_record("same", 1000)
        b = passwords.make_record("same", 1000)
        self.assertNotEqual(a["hash"], b["hash"])

    def test_lockout(self):
        rec = passwords.make_record("good", 1000)
        g = passwords.LoginGuard(rec, 3, 30)
        self.assertEqual(g.try_login("x", now=0), "denied")
        self.assertEqual(g.try_login("x", now=1), "denied")
        self.assertEqual(g.try_login("x", now=2), "denied")
        self.assertEqual(g.try_login("good", now=3), "locked")
        self.assertEqual(g.try_login("good", now=40), "ok")


class IntegrityTests(unittest.TestCase):
    def test_tag_roundtrip(self):
        t = integrity.tag("hello", "k")
        self.assertTrue(integrity.verify("hello", "k", t))

    def test_tamper_detected(self):
        t = integrity.tag("hello", "k")
        self.assertFalse(integrity.verify("hellp", "k", t))
        self.assertFalse(integrity.verify("hello", "other", t))

    def test_open_sealed_raises(self):
        c, t = integrity.seal("QWERTY", "k")
        with self.assertRaises(ValueError):
            integrity.open_sealed("QWERTZ", t, "k")


def benchmark():
    text = "the quick brown fox jumps over the lazy dog " * 2000
    key_hill = [[3, 3], [2, 5]]
    rows = []

    def timed(name, fn):
        start = time.perf_counter()
        out = fn()
        rows.append((name, time.perf_counter() - start))
        return out

    timed("caesar encrypt", lambda: ciphers.caesar(text, 5))
    timed("hill encrypt", lambda: ciphers.hill_encrypt(text, key_hill))
    timed("playfair encrypt", lambda: ciphers.playfair_encrypt(text, "monarchy"))
    print("%d characters" % len(text))
    for name, secs in rows:
        print("%-20s %.4f s" % (name, secs))
    print()
    rate = passwords.hash_rate(100000)
    print("sha256 guesses per second: %d" % rate)
    cases = [
        ("3 chars of 0/1", passwords.BINARY, 3),
        ("4 chars of 1-4", passwords.DIGITS_1_4, 4),
        ("3 chars full set", passwords.FULL, 3),
    ]
    for label, cs, ln in cases:
        pw = cs[-1] * ln
        h = passwords.sha(pw)
        _, tries, secs = passwords.brute_force(h, cs, ln)
        print("%-18s space %-8d tries %-8d %.4f s" % (label, passwords.search_space(cs, ln), tries, secs))


if __name__ == "__main__":
    import sys
    if "bench" in sys.argv:
        benchmark()
    else:
        unittest.main()
