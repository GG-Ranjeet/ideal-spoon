from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from mongoengine.errors import NotUniqueError

from app.models import User
from app.forms import ChangePasswordForm, CheckEmailForm, LoginForm, RegisterForm

auth_bp = Blueprint('auth', __name__, url_prefix="/auth")

@auth_bp.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            # Use Werkzeug to hash the user's password when creating a new user.
            hashed_password = generate_password_hash(
                request.form.get('password'), method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                name=request.form.get("name"),
                email=request.form.get("email"),
                password=hashed_password
            )
            new_user.save()
            login_user(new_user)
            return redirect(url_for('main.home'))
        except NotUniqueError:
            flash("Email already exists. Please log in.", "danger")
            return redirect(url_for('auth.login', email=form.email.data))
    return render_template("register.html", form=form)


@auth_bp.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    # this here is where we redirect from
    email = request.args.get('email')
    if email:
        form.email.data = email
    if form.validate_on_submit():
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.objects(email=email).first()

        if not user:
            flash("Email does not exist. Try again.", "danger")
        elif not check_password_hash(user.password, password):
            flash("Incorrect password.", "danger")
        else:
            if current_user.is_authenticated:   
                print("user is logged in")
            else:
                print("not logged in")
            login_user(user)
            if current_user.is_authenticated:   
                print("user is logged in")
            else:
                print("not logged in")

            return redirect(url_for("main.home"))
    return render_template("login.html", form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@auth_bp.route('/forget', methods=["GET", "POST"])
def forget_password():
    email_form = CheckEmailForm()
    password_form = ChangePasswordForm()

    email_from_url = request.args.get('email')
    if email_from_url:
        password_form.email.data = email_from_url

    if request.method == 'POST':
        if 'password' in request.form and password_form.validate_on_submit():
            hashed_password = generate_password_hash(
                request.form.get('password'), method='pbkdf2:sha256', salt_length=8
            )
            my_email = password_form.email.data
            user = User.objects(email=my_email).first()
            user.password = hashed_password
            user.save()
            login_user(user)

            return redirect(url_for("main.home"))
        
        elif 'email' in request.form and email_form.validate_on_submit():
            my_email = request.form.get('email')
            print(my_email)
            user = User.objects(email=my_email).first()
            if not user:
                flash("Email does not exist. Try again.", "danger")
                return redirect(url_for("auth.forget_password"))

            # either send the link to user for reseting the password or do this
            return redirect(url_for("auth.forget_password", email=my_email))
        
            
    return render_template("reset-password.html", forms=[email_form, password_form], email = email_from_url)