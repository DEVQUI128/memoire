"""
Initialisation de l'application Flask vulnérable.
Même structure que notes-secure mais sans les extensions de sécurité.

[VULN A05] Flask-Talisman absent — aucun header HTTP de sécurité.
           Pas de CSP, pas de HSTS, pas de X-Frame-Options.
"""

from flask import Flask, render_template
from flask_login import LoginManager
from config import config
from app.models import db, User
import os


def create_app(config_name=None):
    """
    Factory function pour créer et configurer l'application Flask.

    Args:
        config_name: Nom de la configuration ('development', 'production', 'testing')

    Returns:
        Flask: Application Flask configurée sans protections de sécurité.
    """

    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # =============================================
    # 1. INITIALISER LES EXTENSIONS
    # =============================================

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Veuillez vous connecter.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        """Charge l'utilisateur depuis la base de données par son ID."""
        return User.query.get(int(user_id))

    # =============================================
    # 2. [VULN A05] AUCUN HEADER DE SÉCURITÉ
    #    Dans notes-secure : Talisman(app, force_https=False,
    #    strict_transport_security=True, content_security_policy={...})
    #    est configuré ici pour protéger l'application.
    #    Ici Talisman n'est pas importé ni utilisé.
    # =============================================

    # =============================================
    # 3. CONTEXTE D'APPLICATION
    # =============================================

    @app.before_request
    def before_request():
        """Exécuté avant chaque requête."""
        pass

    # =============================================
    # 4. ENREGISTRER LES BLUEPRINTS
    # =============================================

    from app.routes import auth_bp, notes_bp, main_bp

    app.register_blueprint(auth_bp, url_prefix='/')
    app.register_blueprint(notes_bp, url_prefix='/notes')
    app.register_blueprint(main_bp, url_prefix='/')

    # =============================================
    # 5. HANDLERS D'ERREURS
    # =============================================

    @app.errorhandler(404)
    def not_found_error(error):
        """Gère les erreurs 404."""
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def forbidden_error(error):
        """Gère les erreurs 403."""
        return render_template('errors/403.html'), 403

    @app.errorhandler(500)
    def internal_error(error):
        """Gère les erreurs 500."""
        db.session.rollback()
        return render_template('errors/500.html'), 500

    # =============================================
    # 6. CRÉER LES TABLES
    # =============================================

    with app.app_context():
        db.create_all()

    return app
