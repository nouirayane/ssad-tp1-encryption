import ciphers


def read_hill_key():
    raw = input("Clé Hill (4 ou 9 nombres séparés par des virgules, ou un mot de 4/9 lettres) : ")
    if "," in raw:
        numbers = [int(x) for x in raw.split(",")]
        size = int(len(numbers) ** 0.5)
        return [numbers[i * size:(i + 1) * size] for i in range(size)]
    return ciphers.key_from_text(raw)


def run_caesar(encrypt):
    text = input("Texte : ")
    n = int(input("Décalage n : "))
    direction = input("Sens (droite / gauche) : ")
    if encrypt:
        print(ciphers.caesar(text, n, direction))
    else:
        print(ciphers.caesar_decrypt(text, n, direction))


def run_hill(encrypt):
    text = input("Texte : ")
    key = read_hill_key()
    if encrypt:
        print(ciphers.hill_encrypt(text, key))
    else:
        print(ciphers.hill_decrypt(text, key))


def run_playfair(encrypt):
    text = input("Texte : ")
    key = input("Mot clé : ")
    if encrypt:
        print(ciphers.playfair_encrypt(text, key))
    else:
        print(ciphers.playfair_strip_padding(ciphers.playfair_decrypt(text, key)))


def main():
    algorithms = {"1": ("César", run_caesar), "2": ("Hill", run_hill), "3": ("Playfair", run_playfair)}
    while True:
        print()
        for number, (name, _) in algorithms.items():
            print(number + " - " + name)
        print("q - Quitter")
        choice = input("Algorithme : ").strip()
        if choice == "q":
            break
        if choice not in algorithms:
            continue
        action = input("(c)hiffrer ou (d)échiffrer : ").strip()
        try:
            algorithms[choice][1](action == "c")
        except ValueError as error:
            print("Erreur :", error)


if __name__ == "__main__":
    main()
