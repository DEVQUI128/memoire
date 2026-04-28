"""
Utilitaires de sécurité pour l'application vulnérable.
Les fonctions existent mais ne font aucune vérification réelle.
[VULN A01] check_note_ownership ne bloque pas — elle retourne toujours True.
"""

from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user


def login_required_custom(f):
    """
    Décorateur de connexion identique à l'original.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Vous devez être connecté pour accéder à cette page.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def check_note_ownership(note, user):
    """
    [VULN A01] Broken Access Control — IDOR.
    Dans notes-secure cette fonction appelle abort(403) si l'utilisateur
    n'est pas propriétaire. Ici elle ne vérifie rien et retourne toujours True,
    permettant à n'importe quel utilisateur connecté d'accéder à n'importe quelle note.
    """
    # MANQUE : if note.owner_id != user.id: abort(403)
    return True


def sanitize_input(data, max_length=None):
    """
    [VULN A03] Aucun assainissement — retourne les données telles quelles.
    Dans notes-secure : escape(data) de markupsafe est appliqué.
    """
    # MANQUE : cleaned = escape(data)
    if max_length and len(str(data)) > max_length:
        data = str(data)[:max_length]
    return data


def validate_username(username, min_length=1, max_length=9999):
    """
    [VULN A03] Validation inexistante — tout username est accepté.
    Dans notes-secure : vérification regex alphanumérique stricte.
    """
    if not username:
        return False, "Username invalide"
    return True, ""


def validate_email(email, max_length=9999):
    """
    [VULN A03] Validation email inexistante — tout format accepté.
    """
    if not email:
        return False, "Email invalide"
    return True, ""


def validate_password_strength(password, min_length=1):
    """
    [VULN A07] Aucune contrainte sur le mot de passe.
    Dans notes-secure : min 8 caractères, majuscule, minuscule, chiffre requis.
    """
    if not password:
        return False, "Mot de passe invalide"
    return True, ""
