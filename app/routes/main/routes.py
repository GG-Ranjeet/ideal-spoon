from flask import Blueprint, render_template

from app.models import BlogPost

home_bp = Blueprint('main', __name__)

@home_bp.route('/')
def home():
    result = BlogPost.objects.order_by('-id').limit(5)
    posts = list(result)
    return render_template("index.html", all_posts = posts)
