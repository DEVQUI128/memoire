#!/usr/bin/env python
"""
Point d'entrée pour lancer l'application Flask vulnérable.
"""

import os
from app import create_app
from app.models import db, User, Note

app = create_app(os.environ.get('FLASK_ENV', 'development'))


@app.shell_context_processor
def make_shell_context():
    """Contexte pour flask shell."""
    return {'db': db, 'User': User, 'Note': Note}


if __name__ == '__main__':
    # [VULN A05] host='0.0.0.0' expose l'app sur toutes les interfaces réseau
    # Dans notes-secure : host='127.0.0.1' (localhost uniquement)
    app.run(
        host='0.0.0.0',
        port=5001,
        debug=True,
        use_reloader=True
    )
