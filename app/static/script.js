/**
 * NOTES SÉCURISÉES - JavaScript Principal
 * Gestion des interactions côté client
 */

// ====================================================
// Fermeture des alertes
// ====================================================

document.addEventListener('DOMContentLoaded', function() {
    // Auto-close alerts après 5 secondes
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.3s ease';
            alert.style.opacity = '0';
            setTimeout(() => {
                alert.style.display = 'none';
            }, 300);
        }, 5000);
    });
    
    // Fermeture manuelle des alertes
    const closeButtons = document.querySelectorAll('.alert-close');
    closeButtons.forEach(button => {
        button.addEventListener('click', function() {
            this.parentElement.parentElement.style.display = 'none';
        });
    });
});

// ====================================================
// Confirmation de suppression
// ====================================================

function confirmDelete(message = 'Êtes-vous sûr de vouloir supprimer cet élément?') {
    return confirm(message);
}

// ====================================================
// Validation de formulaires (frontend)
// ====================================================

function validateNoteForm() {
    const title = document.querySelector('input[name="title"]');
    const content = document.querySelector('textarea[name="content"]');
    
    if (title && title.value.trim().length === 0) {
        alert('Le titre ne peut pas être vide');
        return false;
    }
    
    if (content && content.value.trim().length === 0) {
        alert('Le contenu ne peut pas être vide');
        return false;
    }
    
    return true;
}

// ====================================================
// Notifications utilisateur
// ====================================================

function showNotification(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.innerHTML = `
        <div class="alert-container">
            ${message}
            <button class="alert-close" onclick="this.parentElement.parentElement.style.display='none';">&times;</button>
        </div>
    `;
    
    // Insérer après la navbar
    const navbar = document.querySelector('.navbar');
    if (navbar) {
        navbar.parentNode.insertBefore(alertDiv, navbar.nextSibling);
    } else {
        document.body.insertBefore(alertDiv, document.body.firstChild);
    }
    
    // Auto-fermeture
    setTimeout(() => {
        alertDiv.style.transition = 'opacity 0.3s ease';
        alertDiv.style.opacity = '0';
        setTimeout(() => {
            alertDiv.remove();
        }, 300);
    }, 5000);
}

// ====================================================
// Format de texte
// ====================================================

function truncateText(text, maxLength = 100) {
    if (text.length > maxLength) {
        return text.substring(0, maxLength) + '...';
    }
    return text;
}

// ====================================================
// Gestion du clavier
// ====================================================

document.addEventListener('keydown', function(event) {
    // Ctrl+S pour sauvegarder (si un formulaire est présent)
    if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        const form = document.querySelector('form');
        if (form && form.querySelector('button[type="submit"]')) {
            form.submit();
        }
    }
    
    // Échap pour fermer les modales (si utile)
    if (event.key === 'Escape') {
        // À implémenter si des modales sont ajoutées
    }
});

// ====================================================
// Amélioration UX
// ====================================================

// Ajouter des animations au chargement
document.addEventListener('DOMContentLoaded', function() {
    // Animation des cartes
    const cards = document.querySelectorAll('.note-card, .feature-card, .card');
    cards.forEach((card, index) => {
        card.style.animation = `fadeInUp 0.5s ease ${index * 0.1}s forwards`;
        card.style.opacity = '0';
    });
});

// Animation CSS
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);

// ====================================================
// Sécurité - Validation côté client
// ====================================================

/**
 * Valide qu'un username respecte les règles
 */
function validateUsername(username) {
    if (!username || username.length < 3 || username.length > 50) {
        return false;
    }
    return /^[a-zA-Z0-9_]+$/.test(username);
}

/**
 * Valide qu'un email est valide
 */
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Valide la force d'un mot de passe
 */
function validatePasswordStrength(password) {
    if (password.length < 8) {
        return { valid: false, reason: 'Minimum 8 caractères' };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, reason: 'Doit contenir une majuscule' };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, reason: 'Doit contenir une minuscule' };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, reason: 'Doit contenir un chiffre' };
    }
    return { valid: true };
}

// ====================================================
// Gestion du formulaire de registration (optionnel)
// ====================================================

const registrationForm = document.querySelector('form');
if (registrationForm && window.location.pathname.includes('register')) {
    const passwordInput = registrationForm.querySelector('input[name="password"]');
    const passwordConfirmInput = registrationForm.querySelector('input[name="password_confirm"]');
    
    // Afficher la force du mot de passe en temps réel
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            const strength = validatePasswordStrength(this.value);
            if (!strength.valid) {
                // Feedback optionnel
            }
        });
    }
}
