from datetime import date, datetime

import bleach
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.models import BlogPost, Comment
from app.utils.decorators import admin_and_author_only, admin_or_author_only
from app.forms import CommentForm, CreatePostForm

post_bp = Blueprint("post", __name__, url_prefix="/post")

@post_bp.route('/all-posts')
def show_all_posts():
    # Get the 'page' query param from URL, default to 1
    page = request.args.get('page', 1, type=int)
    per_page = 1
    
    # Select all posts, ordered by newest first (using ID)
    # db.paginate automatically handles the slicing
    pagination = BlogPost.objects.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    # db.select(BlogPost).order_by(BlogPost.id.desc())
    
    return render_template("all-posts.html", pagination=pagination)

@post_bp.route("/post/<post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.objects.get_or_404(pk=post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        clean_text = bleach.clean(
            form.comment.data,
            tags=[],
            strip=True
        )
        new_comment = Comment(
            text=clean_text,
            author=current_user,
            parent_post=requested_post
        )
        new_comment.save()

    return render_template("post.html", post=requested_post, form=form)


@post_bp.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_or_author_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date = datetime.now()
        )
        new_post.save()
        return redirect(url_for("home"))
    return render_template("make-post.html", form=form)


@post_bp.route("/edit-post/<post_id>", methods=["GET", "POST"])
@login_required
@admin_and_author_only
def edit_post(post_id):
    post = BlogPost.objects.get_or_404(pk=post_id)
    edit_form = CreatePostForm(obj=post)
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        post.save()
        return redirect(url_for("post.show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@post_bp.route("/delete/<post_id>")
@login_required
@admin_and_author_only
def delete_post(post_id):
    post_to_delete = BlogPost.objects.get_or_404(pk=post_id)
    if post_to_delete.author != current_user:
        abort(403, description="Not authorised.")

    post_to_delete.delete()
    return redirect(url_for('home'))

