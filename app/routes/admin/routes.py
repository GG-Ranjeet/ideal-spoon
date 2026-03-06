from flask import Blueprint, render_template
from flask_login import login_required

from app.models import BlogPost, User
from app.utils.decorators import admin_only

admin_bp = Blueprint('admin', __name__)

@admin_bp.route("/admin")
@login_required
@admin_only
def admin_dashboard():
    posts = list(BlogPost.objects())
    users = list(User.objects())
    admins = list(User.objects(is_admin=True))
    return render_template(
        "admin.html",
        posts=posts,
        users=users,
        admins=admins,
        total_posts=len(posts),
        total_users=len(users)
    )