import random
import unittest

import ciphers


class CaesarTests(unittest.TestCase):
    def test_roundtrip_both_directions(self):
        msg = "Hello, World! xyz"
        for n in range(0, 120):
            for d in ("right", "left"):
                enc = ciphers.caesar(msg, n, d)
                self.assertEqual(ciphers.caesar_decrypt(enc, n, d), msg)

    def test_known_value(self):
        self.assertEqual(ciphers.caesar("ABC xyz", 3, "right"), "DEF ABC")
        self.assertEqual(ciphers.caesar("DEF ABC", 3, "left"), "ABC xyz")

    def test_alphabet_has_52_letters(self):
        self.assertEqual(len(ciphers.caesar_bruteforce("abc")), 52)
        self.assertEqual(ciphers.caesar("z", 1, "right"), "A")
        self.assertEqual(ciphers.caesar("Z", 1, "right"), "a")

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

    def test_padding_removed(self):
        key = [[3, 3], [2, 5]]
        enc = ciphers.hill_encrypt("BONJOUR", key)
        plain = ciphers.hill_decrypt(enc, key)
        self.assertEqual(plain, "BONJOURX")
        self.assertEqual(ciphers.hill_strip_padding(plain, 2), "BONJOUR")

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


class WeakKeyTests(unittest.TestCase):
    def test_caesar_identity_shift(self):
        for n in (0, 52, -104):
            with self.assertRaises(ValueError):
                ciphers.check_caesar_key(n)
        ciphers.check_caesar_key(3)

    def test_hill_identity_matrix(self):
        with self.assertRaises(ValueError):
            ciphers.check_hill_key([[1, 0], [0, 1]])
        with self.assertRaises(ValueError):
            ciphers.check_hill_key([[27, 0], [0, 1]])
        ciphers.check_hill_key([[3, 3], [2, 5]])

    def test_playfair_short_key(self):
        for key in ("", "123", "aab"):
            with self.assertRaises(ValueError):
                ciphers.check_playfair_key(key)
        ciphers.check_playfair_key("monarchy")


if __name__ == "__main__":
    unittest.main()
