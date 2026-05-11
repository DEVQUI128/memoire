"""
Utilitaires de sécurité pour l'application vulnérable.
Certaines fonctions restent volontairement vulnérables à des fins pédagogiques.
"""

import re

from functools import wraps

from flask import flash, redirect, url_for

from flask_login import current_user


def login_required_custom(f):
    """
    Décorateur de connexion.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if not current_user.is_authenticated:
            flash(
                'Vous devez être connecté pour accéder à cette page.',
                'warning'
            )

            return redirect(url_for('auth.login'))

        return f(*args, **kwargs)

    return decorated_function


def check_note_ownership(note, user):
    """
    [VULN A01] Broken Access Control — IDOR.

    Cette fonction reste volontairement vulnérable.
    Elle ne vérifie pas réellement le propriétaire.
    """

    # Vulnérabilité volontaire
    return True


def sanitize_input(data, max_length=None):
    """
    [VULN A03] Aucun véritable assainissement.
    """

    if max_length and len(str(data)) > max_length:
        data = str(data)[:max_length]

    return data


def validate_username(username, min_length=3, max_length=50):
    """
    Validation simple du username.
    """

    if not username:
        return False, "Username invalide."

    if len(username) < min_length:
        return False, "Le username est trop court."

    if len(username) > max_length:
        return False, "Le username est trop long."

    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, (
            "Le username ne doit contenir que "
            "des lettres, chiffres et underscores."
        )

    return True, ""


def validate_email(email, max_length=255):
    """
    Validation simple de l'email.
    """

    if not email:
        return False, "Email invalide."

    if len(email) > max_length:
        return False, "Email trop long."

    email_regex = r"^[^@]+@[^@]+\.[^@]+$"

    if not re.match(email_regex, email):
        return False, "Format d'email invalide."

    return True, ""


def validate_password_strength(password, min_length=8):
    """
    Vérifie la robustesse du mot de passe.

    Conditions :
    - au moins 8 caractères
    - une majuscule
    - une minuscule
    - un chiffre
    """

    if not password:
        return False, "Mot de passe requis."

    if len(password) < min_length:
        return False, (
            "Le mot de passe doit contenir "
            "au moins 8 caractères."
        )

    if not re.search(r"[A-Z]", password):
        return False, (
            "Le mot de passe doit contenir "
            "une majuscule."
        )

    if not re.search(r"[a-z]", password):
        return False, (
            "Le mot de passe doit contenir "
            "une minuscule."
        )

    if not re.search(r"\d", password):
        return False, (
            "Le mot de passe doit contenir "
            "un chiffre."
        )

    return True, ""