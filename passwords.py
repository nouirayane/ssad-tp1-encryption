import hashlib
import itertools
import os
import string
import time
import hmac

BINARY = "01"
DIGITS_1_4 = "1234"
FULL = string.ascii_lowercase + string.ascii_uppercase + string.digits + "+*-_@#$!?%&="

WORDLIST = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "letmein",
    "dragon", "111111", "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321", "superman", "qazwsx",
    "football", "admin", "welcome", "login", "azerty", "algeria", "usthb",
    "alger", "bonjour", "soleil", "123", "000", "111", "1234", "4321", "1111",
    "2222", "3333", "4444", "1212", "1234abc", "a1b2", "Zz9+", "Ab1*", "xYz", "Pa5*",
]


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def search_space(charset, length):
    return len(set(charset)) ** length


def dictionary_attack(target_hash, words=None):
    words = WORDLIST if words is None else words
    start = time.perf_counter()
    tries = 0
    for w in words:
        tries += 1
        if sha(w) == target_hash:
            return w, tries, time.perf_counter() - start
    return None, tries, time.perf_counter() - start


def brute_force(target_hash, charset, length):
    start = time.perf_counter()
    tries = 0
    h = hashlib.sha256
    goal = bytes.fromhex(target_hash)
    for combo in itertools.product(charset, repeat=length):
        tries += 1
        if h("".join(combo).encode()).digest() == goal:
            return "".join(combo), tries, time.perf_counter() - start
    return None, tries, time.perf_counter() - start


def combined_attack(target_hash, charset, length):
    found, t1, s1 = dictionary_attack(target_hash)
    if found is not None and len(found) == length and set(found) <= set(charset):
        return found, t1, s1, "dictionnaire"
    found, t2, s2 = brute_force(target_hash, charset, length)
    return found, t1 + t2, s1 + s2, "force brute"


def hash_rate(samples=200000):
    start = time.perf_counter()
    for i in range(samples):
        sha(str(i))
    return samples / (time.perf_counter() - start)


def estimate_seconds(space, rate):
    return space / rate / 2


def human_time(seconds):
    if seconds < 1e-3:
        return "%.0f µs" % (seconds * 1e6)
    if seconds < 1:
        return "%.1f ms" % (seconds * 1e3)
    if seconds < 60:
        return "%.1f s" % seconds
    if seconds < 3600:
        return "%.1f min" % (seconds / 60)
    if seconds < 86400:
        return "%.1f h" % (seconds / 3600)
    if seconds < 86400 * 365:
        return "%.1f jours" % (seconds / 86400)
    years = seconds / 86400 / 365
    if years < 1000:
        return "%.1f ans" % years
    return "%.1e ans" % years


ITERATIONS = 200000


def make_record(password, iterations=ITERATIONS):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return {"salt": salt, "iterations": iterations, "hash": digest}


def check_record(record, attempt):
    digest = hashlib.pbkdf2_hmac("sha256", attempt.encode(), record["salt"], record["iterations"])
    return hmac.compare_digest(digest, record["hash"])


def strength_problems(password):
    problems = []
    if len(password) < 10:
        problems.append("moins de 10 caractères")
    if password.lower() in WORDLIST:
        problems.append("figure dans la liste des mots de passe courants")
    if not any(c.islower() for c in password):
        problems.append("aucune minuscule")
    if not any(c.isupper() for c in password):
        problems.append("aucune majuscule")
    if not any(c.isdigit() for c in password):
        problems.append("aucun chiffre")
    if not any(c in "+*-_@#$!?%&=" for c in password):
        problems.append("aucun caractère spécial")
    return problems


class LoginGuard:
    def __init__(self, record, max_failures=3, lock_seconds=30):
        self.record = record
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self.failures = 0
        self.locked_until = 0.0

    def try_login(self, attempt, now=None):
        now = time.monotonic() if now is None else now
        if now < self.locked_until:
            return "locked"
        if check_record(self.record, attempt):
            self.failures = 0
            return "ok"
        self.failures += 1
        if self.failures >= self.max_failures:
            self.locked_until = now + self.lock_seconds
            self.failures = 0
        return "denied"
