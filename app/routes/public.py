from flask import Blueprint, render_template, abort, request, redirect, url_for, flash
from app.extensions import db, limiter
from app.models.client_request import ClientRequest

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


@public_bp.route('/demande-acces', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def demande_acces():
    if request.method == 'POST':
        client_name = request.form.get('client_name', '').strip()
        organization = request.form.get('organization', '').strip()
        description = request.form.get('description', '').strip()
        contact_name = request.form.get('contact_name', '').strip()
        contact_email = request.form.get('contact_email', '').strip().lower()
        redirect_uris = [
            u.strip() for u in request.form.get('redirect_uris', '').splitlines() if u.strip()
        ]
        is_confidential = request.form.get('client_type') == 'confidential'
        requested_scopes = request.form.getlist('scopes') or ['openid']

        errors = []
        if not client_name:
            errors.append("Le nom de l'application est requis.")
        if not contact_name:
            errors.append("Votre nom est requis.")
        if not contact_email or '@' not in contact_email:
            errors.append("Une adresse e-mail de contact valide est requise.")
        if not description:
            errors.append("Une description de l'application est requise.")
        if not redirect_uris:
            errors.append("Au moins une URI de redirection est requise.")

        if errors:
            for err in errors:
                flash(err, 'danger')
            return render_template('demande-acces.html', form=request.form)

        req = ClientRequest(
            client_name=client_name,
            organization=organization or None,
            description=description,
            redirect_uris=redirect_uris,
            requested_scopes=requested_scopes,
            is_confidential=is_confidential,
            contact_name=contact_name,
            contact_email=contact_email,
        )
        db.session.add(req)
        db.session.commit()
        flash(
            "Votre demande a été soumise avec succès. Vous recevrez vos identifiants "
            "par e-mail après validation par un administrateur.",
            'success',
        )
        return redirect(url_for('public.demande_acces'))
    return render_template('demande-acces.html', form={})
