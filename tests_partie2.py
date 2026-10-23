import random
import unittest

import ciphers


class CaesarTests(unittest.TestCase):
    def test_roundtrip_both_directions(self):
        msg = "Hello, World! xyz Zed"
        for n in range(0, 120):
            for d in ("right", "left"):
                enc = ciphers.caesar(msg, n, d)
                self.assertEqual(ciphers.caesar_decrypt(enc, n, d), msg)

    def test_known_value(self):
        self.assertEqual(ciphers.caesar("ABC xyz", 3, "right"), "DEFcABC")
        self.assertEqual(ciphers.caesar("DEFcABC", 3, "left"), "ABC xyz")

    def test_alphabet_has_53_symbols(self):
        self.assertEqual(len(ciphers.caesar_bruteforce("abc")), 53)
        self.assertEqual(ciphers.caesar("z", 1, "right"), "A")
        self.assertEqual(ciphers.caesar("Z", 1, "right"), " ")
        self.assertEqual(ciphers.caesar(" ", 1, "right"), "a")

    def test_spaces_are_encrypted(self):
        enc = ciphers.caesar("a b c", 5)
        self.assertNotIn(" ", enc)

    def test_bruteforce_contains_plaintext(self):
        enc = ciphers.caesar("attack at dawn", 7)
        self.assertIn("attack at dawn", [t for _, t in ciphers.caesar_bruteforce(enc)])

    def test_frequency_guess(self):
        text = "Be sure to keep the secret between the three of them, never tell the others"
        enc = ciphers.caesar(text, 11)
        self.assertEqual(ciphers.caesar_frequency_guess(enc), 11)


class HillTests(unittest.TestCase):
    key = [[4, 5], [3, 2]]

    def test_known_value(self):
        self.assertEqual(ciphers.hill_encrypt("HELP", self.key), "VCLJ")
        self.assertEqual(ciphers.hill_decrypt("VCLJ", self.key), "HELP")

    def test_spaces_are_kept(self):
        enc = ciphers.hill_encrypt("BONJOUR LE MONDE", self.key)
        dec = ciphers.hill_decrypt(enc, self.key)
        self.assertEqual(ciphers.hill_strip_padding(dec, 2), "BONJOUR LE MONDE")

    def test_padding_removed(self):
        enc = ciphers.hill_encrypt("BONJOUR", self.key)
        plain = ciphers.hill_decrypt(enc, self.key)
        self.assertEqual(plain, "BONJOUR ")
        self.assertEqual(ciphers.hill_strip_padding(plain, 2), "BONJOUR")

    def test_roundtrip_random_keys(self):
        rnd = random.Random(4)
        done = 0
        while done < 40:
            n = rnd.choice([2, 3])
            key = [[rnd.randrange(27) for _ in range(n)] for _ in range(n)]
            try:
                ciphers.mat_inverse_mod(key)
            except ValueError:
                continue
            msg = "".join(rnd.choice(ciphers.HILL_ALPHABET) for _ in range(n * 5))
            self.assertEqual(ciphers.hill_decrypt(ciphers.hill_encrypt(msg, key), key), msg)
            done += 1

    def test_bad_key_rejected(self):
        with self.assertRaises(ValueError):
            ciphers.hill_encrypt("HELLO", [[3, 3], [2, 5]])
        with self.assertRaises(ValueError):
            ciphers.hill_encrypt("HELLO", [[2, 4], [1, 2]])

    def test_known_plaintext_attack(self):
        plain = "MEET ME AT NOON"
        enc = ciphers.hill_encrypt(plain, self.key)
        self.assertEqual(ciphers.hill_known_plaintext(plain, enc, 2), self.key)


class PlayfairTests(unittest.TestCase):
    def roundtrip(self, text, key="monarchy"):
        enc = ciphers.playfair_encrypt(text, key)
        return ciphers.playfair_strip_padding(ciphers.playfair_decrypt(enc, key))

    def test_square_has_49_distinct_symbols(self):
        square = ciphers.playfair_square("monarchy")
        self.assertEqual(len(square), 49)
        self.assertEqual(len(set(square)), 49)

    def test_i_and_j_are_different(self):
        self.assertEqual(self.roundtrip("JAVA"), "JAVA")
        self.assertEqual(self.roundtrip("JUILLET"), "JUILLET")
        self.assertNotEqual(ciphers.playfair_encrypt("I", "monarchy"), ciphers.playfair_encrypt("J", "monarchy"))

    def test_spaces_digits_and_x_are_kept(self):
        for text in ("RDV A 14H30", "MAX", "AXA", "MAXX", "HELLO WORLD", "BALLOON"):
            self.assertEqual(self.roundtrip(text), text)

    def test_lowercase_and_accents(self):
        self.assertEqual(self.roundtrip("Élève à l'école"), "ELEVE A L'ECOLE")

    def test_odd_length(self):
        enc = ciphers.playfair_encrypt("abc", "key")
        self.assertEqual(len(enc) % 2, 0)

    def test_random_texts(self):
        rnd = random.Random(7)
        symbols = ciphers.PLAYFAIR_ALPHABET.replace(ciphers.PAD, "")
        for _ in range(200):
            text = "".join(rnd.choice(symbols) for _ in range(rnd.randrange(1, 40)))
            self.assertEqual(self.roundtrip(text), text)


class WeakKeyTests(unittest.TestCase):
    def test_caesar_identity_shift(self):
        for n in (0, 53, -106):
            with self.assertRaises(ValueError):
                ciphers.check_caesar_key(n)
        ciphers.check_caesar_key(3)

    def test_hill_identity_matrix(self):
        with self.assertRaises(ValueError):
            ciphers.check_hill_key([[1, 0], [0, 1]])
        with self.assertRaises(ValueError):
            ciphers.check_hill_key([[28, 0], [0, 1]])
        ciphers.check_hill_key([[4, 5], [3, 2]])

    def test_playfair_short_key(self):
        for key in ("", "   ", "aab"):
            with self.assertRaises(ValueError):
                ciphers.check_playfair_key(key)
        ciphers.check_playfair_key("monarchy")
        ciphers.check_playfair_key("1234")


if __name__ == "__main__":
    unittest.main()
