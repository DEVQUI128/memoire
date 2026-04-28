"""
Formulaires de l'application vulnérable.
[VULN A05] WTF_CSRF_ENABLED = False donc form.hidden_tag() ne génère pas de token CSRF.
[VULN A03] Aucune validation stricte des champs — tout est accepté.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired


class RegistrationForm(FlaskForm):
    """
    Formulaire d'inscription sans validation sécurisée.

    [VULN A03] Aucune validation de format sur username ou email.
    [VULN A07] Aucune contrainte de complexité sur le mot de passe.
    [VULN A05] Pas de token CSRF (WTF_CSRF_ENABLED = False dans config).

    Dans notes-secure : validators Length, Email, EqualTo, et validate_password()
    sont utilisés pour imposer des règles strictes.
    """

    username = StringField(
        'Nom d\'utilisateur',
        validators=[DataRequired(message='Le nom d\'utilisateur est requis')]
        # MANQUE : Length(min=3, max=50)
        # MANQUE : validate_username() — regex alphanumérique
    )

    email = StringField(
        'Email',
        validators=[DataRequired(message='L\'email est requis')]
        # MANQUE : Email(message='L\'email doit être valide')
        # MANQUE : validate_email() — unicité
    )

    password = PasswordField(
        'Mot de passe',
        validators=[DataRequired(message='Le mot de passe est requis')]
        # MANQUE : Length(min=8)
        # MANQUE : validate_password() — majuscule, minuscule, chiffre
    )

    # [VULN A07] Pas de champ de confirmation du mot de passe
    # MANQUE : password_confirm = PasswordField(..., validators=[EqualTo('password')])

    submit = SubmitField('S\'inscrire')


class LoginForm(FlaskForm):
    """
    Formulaire de connexion.
    [VULN A07] Aucune protection contre le brute-force.
    """

    username = StringField(
        'Nom d\'utilisateur',
        validators=[DataRequired(message='Le nom d\'utilisateur est requis')]
    )

    password = PasswordField(
        'Mot de passe',
        validators=[DataRequired(message='Le mot de passe est requis')]
    )

    submit = SubmitField('Se connecter')


class NoteForm(FlaskForm):
    """
    Formulaire de création/modification de note.
    [VULN A03] Aucune limite de longueur — pas de protection contre les payloads énormes.
    [VULN A03] Le contenu XSS ne sera pas filtré côté serveur.

    Dans notes-secure : Length(max=200) pour titre, Length(max=5000) pour contenu.
    """

    title = StringField(
        'Titre',
        validators=[DataRequired(message='Le titre est requis')]
        # MANQUE : Length(min=1, max=200)
    )

    content = TextAreaField(
        'Contenu',
        validators=[DataRequired(message='Le contenu est requis')]
        # MANQUE : Length(min=1, max=5000)
    )

    submit = SubmitField('Sauvegarder')
