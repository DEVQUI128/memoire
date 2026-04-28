# Notes App — Version Vulnérable (Scénario A)

> ⚠️ **AVERTISSEMENT** : Application contenant des vulnérabilités intentionnelles
> à des fins pédagogiques. Ne jamais déployer en production.

## Objectif

Cette application constitue le **Scénario A** de l'étude DevSecOps :
développement sans intégration de la sécurité.
Elle est à comparer avec `notes-secure` (Scénario B).

## Structure — identique à notes-secure

```
notes-vuln/
├── config.py              ← Clé faible, CSRF off, cookies non sécurisés
├── run.py                 ← host=0.0.0.0 (toutes interfaces)
├── requirements.txt       ← Sans Flask-Talisman ni semgrep
└── app/
    ├── __init__.py        ← Sans Talisman — aucun header de sécurité
    ├── models.py          ← Mots de passe en clair (pas de hash)
    ├── routes.py          ← Injections SQL, IDOR, open redirect
    ├── security.py        ← check_note_ownership() ne bloque pas
    ├── forms.py           ← Aucune validation stricte
    ├── static/            ← Identique
    └── templates/         ← Mêmes fichiers avec | safe (XSS)
        ├── base.html
        ├── home.html
        ├── dashboard.html
        ├── auth/login.html
        ├── auth/register.html
        ├── notes/create.html
        ├── notes/view.html
        ├── notes/edit.html
        └── errors/403.html | 404.html | 500.html
```

## Vulnérabilités par fichier

| Fichier | OWASP | Description |
|---|---|---|
| `config.py` | A02, A05 | Clé "secret123", CSRF off, cookies non sécurisés |
| `models.py` | A02 | `password` en clair, `set_password()` sans hash |
| `security.py` | A01 | `check_note_ownership()` retourne toujours True |
| `forms.py` | A03, A07 | Aucune validation de format ni de complexité |
| `routes.py` | A03 | SQL brut concaténé dans `login()` et `register()` |
| `routes.py` | A01 | IDOR : `view_note`, `edit_note`, `delete_note` |
| `routes.py` | A07 | Messages différenciés selon existence du username |
| `routes.py` | A09 | `str(e)` exposé dans les flash messages |
| `routes.py` | A10 | `next=` non validé dans `login()` |
| `__init__.py` | A05 | Talisman absent — aucun header HTTP de sécurité |
| `templates/notes/view.html` | A03 | `{{ note.title \| safe }}`, `{{ note.content \| safe }}` |
| `templates/dashboard.html` | A03 | `{{ note.title \| safe }}`, `{{ note.content \| safe }}` |

## Installation

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
python run.py
# => http://localhost:5001
```
