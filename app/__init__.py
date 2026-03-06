import hashlib

from flask import Flask
from flask_mongoengine import MongoEngine
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import LoginManager
from config import Config


db = MongoEngine()
ckeditor = CKEditor()
bootstrap = Bootstrap5()
login_manager = LoginManager()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    ckeditor.init_app(app)
    bootstrap.init_app(app)
    login_manager.init_app(app)

    
    from .models import User    
    from .routes.admin.routes import admin_bp
    from .routes.main.routes import home_bp
    from .routes.auth.routes import auth_bp
    from .routes.posts.routes import post_bp
    from .routes.other.routes import other_bp
    from .utils.helper import gravatar

    app.register_blueprint(admin_bp)
    app.register_blueprint(home_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(post_bp)
    app.register_blueprint(other_bp)

    @login_manager.user_loader
    def load_user(user_id):
        user_id = str(user_id)
        return User.objects(pk=user_id).first()

    @app.template_filter('gravatar')
    def gravatar_url(email, size=100, default='identicon', rating='g'):
        url = 'https://www.gravatar.com/avatar'
        hash_value = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
        return f"{url}/{hash_value}?s={size}&d={default}&r={rating}"

    return app
