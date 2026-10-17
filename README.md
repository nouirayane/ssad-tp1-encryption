# Framework de chiffrement (SSAD TP1)

Travail pratique du cours SSAD, USTHB 2026-2027. Python 3, bibliothèque standard uniquement.

## Lancement

```
python app.py
python partie2.py
python tests.py
python tests_partie2.py
python tests.py bench
```

## Contenu

| Fichier | Rôle |
|---------|------|
| `ciphers.py` | César, Hill, Playfair et leurs attaques (autonome, sans dépendance vers les autres fichiers) |
| `partie2.py` | Programme console pour tester la partie 2 seule |
| `passwords.py` | Cas de mots de passe, attaques par dictionnaire et force brute, PBKDF2, verrouillage |
| `integrity.py` | Empreinte SHA-256 et tag HMAC |
| `app.py` | Interface Tkinter |
| `tests_partie2.py` | Tests des chiffrements |
| `tests.py` | Tests mots de passe et intégrité, banc d'essai |
| `code_interface.pdf` | Code de la partie 1 |
| `code_chiffrements.pdf` | Code de la partie 2 avec explications |
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
