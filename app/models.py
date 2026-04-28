"""
Modèles de base de données pour l'application vulnérable.
[VULN A02] Mots de passe stockés en clair — aucun hash.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """
    Modèle utilisateur.

    [VULN A02] Le champ password stocke le mot de passe en texte clair.
    Dans notes-secure, ce champ s'appelle password_hash et utilise PBKDF2.
    """
    __tablename__ = 'users'

    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(9999), unique=True, nullable=False)
    email      = db.Column(db.String(9999), unique=True, nullable=False)
    # [VULN A02] Stockage du mot de passe en CLAIR
    password   = db.Column(db.String(9999), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    notes = db.relationship('Note', backref='author', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        """
        [VULN A02] Stocke le mot de passe en clair sans aucun hash.
        Dans notes-secure : generate_password_hash(password, method='pbkdf2:sha256')
        """
        self.password = password

    def check_password(self, password):
        """
        [VULN A02] Comparaison directe en clair — aucun check_password_hash.
        """
        return self.password == password

    def __repr__(self):
        return f'<User {self.username}>'


class Note(db.Model):
    """
    Modèle pour les notes de l'utilisateur.
    """
    __tablename__ = 'notes'

    id         = db.Column(db.Integer, primary_key=True)
    title      = db.Column(db.String(9999), nullable=False)
    content    = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner_id   = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f'<Note {self.title}>'
