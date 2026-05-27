"""
Configuration sécurisée de l'application Flask.
Version corrigée pour le scénario DevSecOps.
"""

import os


class Config:
    """Configuration de base sécurisée."""

    # =============================================
    # CLÉ SECRÈTE
    # =============================================

    # Utilise une variable d'environnement
    SECRET_KEY = os.environ.get(
        'SECRET_KEY',
        'change-this-secret-key-in-production'
    )

    # =============================================
    # BASE DE DONNÉES
    # =============================================

    SQLALCHEMY_DATABASE_URI = 'sqlite:///notes_vuln.db'

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # =============================================
    # SÉCURITÉ DES COOKIES
    # =============================================

    # Cookie uniquement envoyé en HTTPS
    SESSION_COOKIE_SECURE = False  # True en production

    # Empêche l'accès JavaScript au cookie
    SESSION_COOKIE_HTTPONLY = True

    # Protection CSRF moderne
    SESSION_COOKIE_SAMESITE = 'Lax'

    # =============================================
    # PROTECTION CSRF
    # =============================================

    WTF_CSRF_ENABLED = True

    WTF_CSRF_TIME_LIMIT = None

    # =============================================
    # RECHARGEMENT TEMPLATES
    # =============================================

    SEND_FILE_MAX_AGE_DEFAULT = 0

    TEMPLATES_AUTO_RELOAD = True

    # =============================================
    # LIMITES DE VALIDATION
    # =============================================

    MAX_USERNAME_LENGTH = 50

    MIN_USERNAME_LENGTH = 3

    MAX_EMAIL_LENGTH = 120

    MIN_PASSWORD_LENGTH = 8

    MAX_NOTE_TITLE_LENGTH = 100

    MAX_NOTE_CONTENT_LENGTH = 5000


class DevelopmentConfig(Config):
    """
    Configuration développement.
    """

    DEBUG = True

    TESTING = False


class ProductionConfig(Config):
    """
    Configuration production.
    """

    DEBUG = False

    TESTING = False


class TestingConfig(Config):
    """
    Configuration tests.
    """

    DEBUG = False

    TESTING = True

    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

    WTF_CSRF_ENABLED = True


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}