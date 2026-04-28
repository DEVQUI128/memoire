"""
Configuration de l'application Flask vulnérable.
Scénario A : aucune bonne pratique de sécurité.
"""

import os


class Config:
    """Configuration de base."""

    # [VULN A02] Clé secrète faible codée en dur — jamais de variable d'environnement
    SECRET_KEY = "secret123"

    # Base de données SQLite
    SQLALCHEMY_DATABASE_URI = 'sqlite:///notes_vuln.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # [VULN A05] Cookies de session non sécurisés
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False   # Cookie accessible via JavaScript
    SESSION_COOKIE_SAMESITE = None    # Aucune protection CSRF

    SEND_FILE_MAX_AGE_DEFAULT = 0
    TEMPLATES_AUTO_RELOAD = True

    # [VULN A05] CSRF désactivé
    WTF_CSRF_ENABLED = False

    # Pas de limites de validation
    MAX_USERNAME_LENGTH = 9999
    MIN_USERNAME_LENGTH = 1
    MAX_EMAIL_LENGTH = 9999
    MIN_PASSWORD_LENGTH = 1
    MAX_NOTE_TITLE_LENGTH = 9999
    MAX_NOTE_CONTENT_LENGTH = 9999


class DevelopmentConfig(Config):
    # [VULN A05] Debug toujours actif
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    # [VULN A05] Debug actif même en production
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'production':  ProductionConfig,
    'testing':     TestingConfig,
    'default':     DevelopmentConfig
}
