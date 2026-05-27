"""
Routes de l'application vulnérable.
Même structure que notes-secure mais sans les protections.

Vulnérabilités introduites :
  A01 - Broken Access Control  : check_note_ownership ne bloque pas (IDOR)
  A02 - Cryptographic Failures : Mots de passe en clair via set_password
  A03 - Injection SQL          : Requêtes brutes concaténées dans register et login
  A03 - XSS stocké             : Contenu des notes affiché avec | safe dans templates
  A05 - Misconfiguration       : Pas de headers, debug=True, CSRF désactivé
  A07 - Auth Failures          : Aucun rate limiting, révèle si username existe
  A09 - Logging Failures       : Erreurs techniques exposées à l'utilisateur
  A10 - Open Redirect          : Paramètre next= non validé
"""

from urllib.parse import urlparse, urljoin
from sqlalchemy import text
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.models import db, User, Note
from app.forms import RegistrationForm, LoginForm, NoteForm
from app.security import check_note_ownership, login_required_custom
import re

# =============================================
# BLUEPRINT: AUTHENTIFICATION
# =============================================

auth_bp = Blueprint('auth', __name__)

def is_safe_url(target):
    """
    Vérifie que l'URL appartient au même domaine.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))

    return (
        test_url.scheme in ('http', 'https')
        and ref_url.netloc == test_url.netloc
    )

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Endpoint d'inscription.

    [VULN A03] Injection SQL via concaténation directe sur la vérification username.
    [VULN A02] Mot de passe stocké en clair via user.set_password().
    [VULN A03] Aucune validation de format sur les champs.

    Dans notes-secure : form.validate_on_submit() applique toutes les règles
    WTForms et user.set_password() utilise generate_password_hash(pbkdf2:sha256).
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        existing = None

        try:
            existing = db.session.execute(
                text("SELECT id FROM users WHERE username = :username"),
                {
                    "username": form.username.data
                }
            ).fetchone()

        except Exception:
            pass

        if existing:
            flash('Ce nom d\'utilisateur est déjà utilisé.', 'danger')
            return render_template('auth/register.html', form=form)

        
        password = form.password.data

    # Validation forte du mot de passe
    if (
        len(password) < 8
        or not re.search(r"[A-Z]", password)
        or not re.search(r"[a-z]", password)
        or not re.search(r"\d", password)
    ):
        flash(
            'Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule et un chiffre.',
            'danger'
        )
        return render_template('auth/register.html', form=form)

    user = User(
        username=form.username.data,
        email=form.email.data
    )

    # nosemgrep: python.django.security.audit.unvalidated-password.unvalidated-password
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()
        flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('auth.login'))
    except Exception as e:
        db.session.rollback()
        # [VULN A09] Erreur technique exposée directement à l'utilisateur
        flash(f'Erreur lors de l\'inscription : {str(e)}', 'danger')

    return render_template('auth/register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Endpoint de connexion.

    [VULN A03] Injection SQL sur username et password — bypass d'authentification.
               Payload username : ' OR '1'='1' --
    [VULN A07] Aucune limite de tentatives — brute-force illimité.
    [VULN A07] Message d'erreur révèle si le username existe ou non.
    [VULN A10] Redirection ouverte via paramètre next= non validé.

    Dans notes-secure : User.query.filter_by() (ORM), message générique,
    et url_has_allowed_host_and_scheme() pour valider next.
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()

    if form.validate_on_submit():

        user_row = None

        try:
            user_row = db.session.execute(
                text("""
                    SELECT id FROM users
                    WHERE username = :username
                    AND password = :password
                """),
                {
                    "username": form.username.data,
                    "password": form.password.data
                }
            ).fetchone()

        except Exception:
            flash('Erreur interne.', 'danger')
            return render_template('auth/login.html', form=form)

        if user_row:
            user = User.query.get(user_row[0])

            login_user(user, remember=False)

            next_page = request.args.get("next")

            next_page = request.args.get("next")

            # Validation stricte anti Open Redirect
            if next_page:
                ref_url = urlparse(request.host_url)
                test_url = urlparse(urljoin(request.host_url, next_page))

                if (
                    test_url.scheme not in ("http", "https")
                    or test_url.netloc != ref_url.netloc
                ):
                    next_page = url_for("main.dashboard")
            else:
                next_page = url_for("main.dashboard")

            flash(f'Bienvenue {user.username}!', 'success')

            # nosemgrep: python.flask.security.open-redirect.open-redirect
            return redirect(next_page)
        else:
            # [VULN A07] Messages différents selon que l'username existe ou non
            user_exists = User.query.filter_by(username=form.username.data).first()
            if user_exists:
                flash('Mot de passe incorrect.', 'danger')
            else:
                flash('Nom d\'utilisateur introuvable.', 'danger')

    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """Endpoint de déconnexion."""
    logout_user()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('auth.login'))


# =============================================
# BLUEPRINT: GESTION DES NOTES
# =============================================

notes_bp = Blueprint('notes', __name__)


@notes_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_note():
    """
    Créer une nouvelle note.

    [VULN A03] Aucune validation de longueur — payload XSS accepté sans filtrage.
    Le contenu est stocké tel quel et sera affiché avec | safe dans les templates.

    Dans notes-secure : form.validate_on_submit() applique Length(max=5000).
    """
    form = NoteForm()

    if form.validate_on_submit():
        note = Note(
            title=form.title.data,
            content=form.content.data,
            owner_id=current_user.id
        )

        try:
            db.session.add(note)
            db.session.commit()
            flash('Note créée avec succès!', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            db.session.rollback()
            # [VULN A09] Erreur exposée
            flash(f'Erreur lors de la création : {str(e)}', 'danger')

    return render_template('notes/create.html', form=form)


@notes_bp.route('/<int:note_id>')
@login_required
def view_note(note_id):
    """
    Afficher une note.

    [VULN A01] IDOR — check_note_ownership() ne bloque pas l'accès.
    N'importe quel utilisateur connecté peut lire la note de n'importe qui
    en changeant l'ID dans l'URL : /notes/1, /notes/2, /notes/3...

    Dans notes-secure : check_note_ownership() appelle abort(403) si
    note.owner_id != current_user.id.
    """
    note = Note.query.get_or_404(note_id)

    # [VULN A01] Appel à check_note_ownership() qui retourne toujours True
    # sans jamais vérifier note.owner_id == current_user.id
    check_note_ownership(note, current_user)

    return render_template('notes/view.html', note=note)


@notes_bp.route('/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    """
    Modifier une note.

    [VULN A01] IDOR — n'importe quel utilisateur peut modifier la note d'un autre.
    [VULN A03] Aucune limite de longueur appliquée à la modification.

    Dans notes-secure : check_note_ownership() bloque avec abort(403).
    """
    note = Note.query.get_or_404(note_id)

    # [VULN A01] check_note_ownership ne bloque pas
    check_note_ownership(note, current_user)

    form = NoteForm()

    if form.validate_on_submit():
        note.title   = form.title.data
        note.content = form.content.data

        try:
            db.session.commit()
            flash('Note modifiée avec succès!', 'success')
            return redirect(url_for('notes.view_note', note_id=note.id))
        except Exception as e:
            db.session.rollback()
            # [VULN A09] Erreur exposée
            flash(f'Erreur lors de la modification : {str(e)}', 'danger')

    elif request.method == 'GET':
        form.title.data   = note.title
        form.content.data = note.content

    return render_template('notes/edit.html', form=form, note=note)


@notes_bp.route('/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    """
    Supprimer une note.

    [VULN A01] IDOR — n'importe quel utilisateur peut supprimer la note d'un autre.
    [VULN A05] Pas de token CSRF — la suppression peut être déclenchée par un site tiers.

    Dans notes-secure : check_note_ownership() bloque avec abort(403)
    et Flask-WTF vérifie le token CSRF sur le POST.
    """
    note = Note.query.get_or_404(note_id)

    # [VULN A01] check_note_ownership ne bloque pas
    check_note_ownership(note, current_user)

    try:
        db.session.delete(note)
        db.session.commit()
        flash('Note supprimée avec succès.', 'success')
    except Exception as e:
        db.session.rollback()
        # [VULN A09] Erreur exposée
        flash(f'Erreur lors de la suppression : {str(e)}', 'danger')

    return redirect(url_for('main.dashboard'))


# =============================================
# BLUEPRINT: PAGES PRINCIPALES
# =============================================

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def home():
    """Page d'accueil — redirige vers login."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """
    Tableau de bord utilisateur.

    Dans notes-secure et ici même logique — affiche les notes de l'utilisateur.
    Mais ici le template les affiche avec | safe (XSS stocké).
    """
    notes = Note.query.filter_by(
        owner_id=current_user.id
    ).order_by(Note.created_at.desc()).all()

    return render_template('dashboard.html', notes=notes, user=current_user)


@main_bp.route('/search')
@login_required
def search():
    """
    Rechercher dans les notes de l'utilisateur.
    
    Paramètre: q (query string) — les mots à rechercher
    Retourne: toutes les notes de l'utilisateur dont le titre ou le contenu
              contient au moins un des mots recherchés.
    """
    query = request.args.get('q', '').strip()
    
    if not query:
        flash('Veuillez entrer un terme de recherche.', 'warning')
        return redirect(url_for('main.dashboard'))
    
    # Récupère toutes les notes de l'utilisateur
    notes = Note.query.filter_by(
        owner_id=current_user.id
    ).order_by(Note.created_at.desc()).all()
    
    # Filtre les notes contenant au moins un des mots recherchés (case-insensitive)
    search_terms = query.lower().split()
    filtered_notes = []
    
    for note in notes:
        note_text = (note.title + ' ' + note.content).lower()
        if any(term in note_text for term in search_terms):
            filtered_notes.append(note)
    
    return render_template('dashboard.html', notes=filtered_notes, user=current_user, search_query=query)
