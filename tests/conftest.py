import pytest
from app import create_app
from app.extensions import db as _db
from app.models.user import User
from app.models.oauth2_client import OAuth2Client
from app.extensions import bcrypt

@pytest.fixture(scope='session')
def app():
    app = create_app('testing')
    with app.app_context():
        _db.create_all()
        # Créer la clé RS256 après les tables
        from app.services.key_service import KeyService
        try:
            KeyService.get_active_key()
        except Exception as e:
            app.logger.warning(f"Erreur création clé RS256 : {e}")
        yield app
        # Ne pas appeler drop_all() : cela supprimerait les tables de la base
        # de données partagée et bloquerait alembic. Les fixtures gèrent leur
        # propre nettoyage via l'approche delete-first.

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def db(app):
    """Fixture DB simple — chaque opération obtient sa propre connexion NullPool.
    Flask-SQLAlchemy 3.x scope la session par thread, donc db.session est le
    même objet dans tout le corps du test (y compris les with app.app_context()
    imbriqués), ce qui permet à db.session.commit() de persister les
    modifications des objets ORM comme test_user sans laisser de connexions
    zombies ouvertes."""
    with app.app_context():
        yield _db
        _db.session.remove()

@pytest.fixture
def test_user(db):
    User.query.filter_by(email='test@example.com').delete()
    db.session.commit()
    user = User(
        username='testuser',
        email='test@example.com',
        password_hash=bcrypt.generate_password_hash('password123').decode('utf-8'),
        is_admin=False,
        is_active=True
    )
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def test_client(db):
    OAuth2Client.query.filter_by(client_id='test_client').delete()
    db.session.commit()
    client = OAuth2Client(
        client_id='test_client',
        client_secret_hash=bcrypt.generate_password_hash('secret').decode('utf-8'),
        client_name='Test Client',
        redirect_uris=['http://localhost/callback'],
        allowed_scopes=['openid', 'profile', 'email'],
        grant_types=['authorization_code', 'refresh_token'],
        is_confidential=True,
        is_active=True
    )
    db.session.add(client)
    db.session.commit()
    return client