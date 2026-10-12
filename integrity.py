import hashlib
import hmac


def digest(message):
    return hashlib.sha256(message.encode()).hexdigest()


def tag(message, secret):
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify(message, secret, received_tag):
    return hmac.compare_digest(tag(message, secret), received_tag)


def seal(ciphertext, secret):
    return ciphertext, tag(ciphertext, secret)


def open_sealed(ciphertext, received_tag, secret):
    if not verify(ciphertext, secret, received_tag):
        raise ValueError("authentification échouée")
    return ciphertext
