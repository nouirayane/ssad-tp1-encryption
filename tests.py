import time
import unittest

import ciphers
import integrity
import passwords


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

    timed("chiffrement cesar", lambda: ciphers.caesar(text, 5))
    timed("chiffrement hill", lambda: ciphers.hill_encrypt(text, key_hill))
    timed("chiffrement playfair", lambda: ciphers.playfair_encrypt(text, "monarchy"))
    print("%d caractères" % len(text))
    for name, secs in rows:
        print("%-20s %.4f s" % (name, secs))
    print()
    rate = passwords.hash_rate(100000)
    print("essais sha256 par seconde : %d" % rate)
    cases = [
        ("3 car. de 0/1", passwords.BINARY, 3),
        ("4 car. de 1 a 4", passwords.DIGITS_1_4, 4),
        ("3 car. ensemble complet", passwords.FULL, 3),
    ]
    for label, cs, ln in cases:
        pw = cs[-1] * ln
        h = passwords.sha(pw)
        _, tries, secs = passwords.brute_force(h, cs, ln)
        print("%-24s espace %-8d essais %-8d %.4f s" % (label, passwords.search_space(cs, ln), tries, secs))


if __name__ == "__main__":
    import sys
    if "bench" in sys.argv:
        benchmark()
    else:
        unittest.main()
