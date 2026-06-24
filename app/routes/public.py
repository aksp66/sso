from flask import Blueprint, render_template, abort

public_bp = Blueprint('public', __name__)

# Liste blanche des pages de documentation (slug -> titre affiché dans la sidebar)
DEVELOPER_DOCS = [
    ('demarrage-rapide', 'Démarrage rapide'),
    ('authentification', 'Authentification OAuth2 + PKCE'),
    ('reference-api', 'Référence API'),
    ('scopes-claims', 'Scopes & claims'),
    ('securite', 'Sécurité & bonnes pratiques'),
    ('erreurs', "Codes d'erreur"),
]

HELP_DOCS = [
    ('creer-un-compte', 'Créer un compte'),
    ('connexion-2fa', 'Se connecter & activer la 2FA'),
    ('gerer-profil', 'Gérer mon profil'),
    ('mot-de-passe-oublie', 'Mot de passe oublié'),
    ('applications-connectees', 'Applications connectées'),
    ('faq', 'Questions fréquentes'),
]


@public_bp.route('/')
def home():
    return render_template('home.html')


@public_bp.route('/docs')
def docs_index():
    return render_template(
        'docs/index.html',
        developer_docs=DEVELOPER_DOCS,
        help_docs=HELP_DOCS,
    )


@public_bp.route('/docs/developers/<slug>')
def docs_developers(slug):
    if slug not in dict(DEVELOPER_DOCS):
        abort(404)
    return render_template(
        f'docs/developers/{slug}.html',
        developer_docs=DEVELOPER_DOCS,
        help_docs=HELP_DOCS,
        active_slug=slug,
        active_section='developers',
    )


@public_bp.route('/docs/aide/<slug>')
def docs_aide(slug):
    if slug not in dict(HELP_DOCS):
        abort(404)
    return render_template(
        f'docs/aide/{slug}.html',
        developer_docs=DEVELOPER_DOCS,
        help_docs=HELP_DOCS,
        active_slug=slug,
        active_section='aide',
    )
