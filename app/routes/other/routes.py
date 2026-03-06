from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.forms import EditProfileForm
from app.models import Message, User

other_bp = Blueprint('other', __name__)

@other_bp.route("/about")
def about():
    result = User.objects(is_admin=True)
    admins = list(result)
    return render_template("about.html", admins=admins)


@other_bp.route("/contact", methods=["GET", "POST"])
def contact():
    # 1. Handle POST request (User submitting form)
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("You must be logged in to send a message.", "danger")
            return redirect(url_for("auth.login"))

        new_message = Message(
            name=current_user.name,       # Auto-fill from logged-in user
            email=current_user.email,     # Auto-fill from logged-in user
            phone=request.form.get("phone"),
            text=request.form.get("message"),
            date=datetime.now()  # e.g. January 01, 2026, 12:00
        )
        new_message.save()

        flash("Message sent! The admin will review it shortly.", "success")
        return redirect(url_for("other.contact"))

    # 2. Handle GET request (Show the page)
    return render_template("contact.html")

@other_bp.route("/profile/<user_id>")
def profile(user_id):
    user = User.objects.get_or_404(pk=user_id)
    return render_template("profile.html", user=user)

@other_bp.route("/edit-profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    form = EditProfileForm(obj=current_user)

    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.bio = form.bio.data
        current_user.linkedin_url = form.linkedin_url.data
        current_user.github_url = form.github_url.data
        current_user.save()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('other.profile', user_id=current_user.pk))
    else:
        flash("Enter valid URL!", "unsuccessful")
        pass
    return render_template("edit-profile.html", form=form)
