# Framework de chiffrement (SSAD TP1)

Travail pratique du cours SSAD, USTHB 2026-2027. Python 3, bibliothèque standard uniquement.

## Lancement

```
python app.py
python tests.py
python tests.py bench
```

## Contenu

| Fichier | Rôle |
|---------|------|
| `ciphers.py` | César, Hill, Playfair et les attaques correspondantes |
| `passwords.py` | Cas de mots de passe, attaques par dictionnaire et force brute, PBKDF2, verrouillage |
| `integrity.py` | Empreinte SHA-256 et tag HMAC |
| `app.py` | Interface Tkinter |
| `tests.py` | Tests unitaires et banc d'essai |
| `report.pdf` | Rapport complet |

## Répartition du travail

| Membre | Tâche |
|--------|-------|
| 1 | Chiffrement de César et ses attaques |
| 2 | Chiffrement de Hill et attaque à clair connu |
| 3 | Chiffrement de Playfair et analyse des digrammes |
| 4 | Attaques sur mots de passe (dictionnaire, force brute) |
| 5 | Protection des mots de passe et intégrité HMAC |
| 6 | Interface, tests, mesures, rapport |
