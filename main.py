from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_required, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from forms import CreatePostForm, LoginForm, RegisterForm, CommentForm, EditProfileForm
import os
import bleach
import smtplib  # For sending email
from forms import ContactForm
from datetime import datetime

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# Create login manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] =  os.environ.get("DB_URI","sqlite:///posts.db")
# app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///posts.db"
db = SQLAlchemy(model_class=Base)
db.init_app(app)

"""-----------------------------------CREATE TABLE IN DB----------------------------"""


class User(UserMixin, db.Model):
    __tablename__ = "user_table"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(1000), nullable=False)
    email: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)

    # --- NEW COLUMNS ---
    bio: Mapped[str] = mapped_column(Text, nullable=True) 
    linkedin_url: Mapped[str] = mapped_column(String(250), nullable=True)
    github_url: Mapped[str] = mapped_column(String(250), nullable=True)
    # -------------------

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")

    is_author = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    def role_names(self):
        roles = []
        if self.is_admin:
            roles.append("Admin")
        if self.is_author:
            roles.append("Author")
        return roles or ["User"]



class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(
        String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # author: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(
        Integer, db.ForeignKey("user_table.id"))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="posts")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(String(1000), nullable=False)

    author_id: Mapped[int] = mapped_column(
        Integer, db.ForeignKey("user_table.id"))
    parent_post: Mapped[int] = mapped_column(
        Integer, db.ForeignKey("blog_posts.id"))

    author = relationship("User", back_populates="comments")
    posts = relationship("BlogPost", back_populates="comments")


class Message(db.Model):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(100), nullable=False)
    phone: Mapped[str] = mapped_column(String(100), nullable=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    date: Mapped[str] = mapped_column(String(100), nullable=False)
    is_read: Mapped[bool] = mapped_column(db.Boolean, default=False)


with app.app_context():
    db.create_all()


"""-----------------------------------AVATAR GEN----------------------------"""
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

"""-----------------------------------HELPER FUNCTION----------------------------"""

"""-----------------------------------DECORATORS----------------------------"""


def admin_and_author_only(func):
    '''
    can only access if the user is logged in and if they are admin or author of the post
    Example - Editing a post with a provided post_id
    \nparam func: post_id
    '''
    @wraps(func)
    def wrapper(*args, **kwargs):
        post_id = kwargs.get("post_id")
        post = BlogPost.query.get_or_404(post_id)

        # Admin can do anything
        if current_user.is_admin:
            return func(*args, **kwargs)

        # Author can edit/delete their own post
        if current_user.is_author and post.author_id == current_user.id:
            return func(*args, **kwargs)

        abort(403, description="Not authorised.")
    return wrapper


def admin_or_author_only(func):
    """
    Accessible for admin and author only 
    Example - Creating a post
    \nparam func: None
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_admin or current_user.is_author:
            return func(*args, **kwargs)
        abort(403, description="Not authorised.")
    return wrapper


def admin_only(func):
    """
    Accessible for admin 
    Example - Admin panel

    :param func: None
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_admin:
            return func(*args, **kwargs)
        abort(403, description="Not authorised.")
    return wrapper


"""-------------------------------------VIEWS-------------------------------"""


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            # Use Werkzeug to hash the user's password when creating a new user.
            hashed_password = generate_password_hash(
                request.form.get('password'), method='pbkdf2', salt_length=8)
            new_user = User(
                name=request.form.get("name"),
                email=request.form.get("email"),
                password=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()
            flash("Email already exists. Please log in.", "danger")
            login_form = LoginForm(
                email=request.form.get('email')
            )
            return redirect(url_for('login', email=form.email.data))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    email = request.args.get('email')
    if email:
        form.email.data = email
    if form.validate_on_submit():
        email = request.form.get("email")
        password = request.form.get("password")
        user = db.session.execute(
            db.select(User).where(User.email == email)).scalar()

        if not user:
            flash("Email does not exist. Try again.", "danger")
        elif not check_password_hash(user.password, password):
            flash("Incorrect password.", "danger")
        else:
            login_user(user)
            return redirect(url_for("home"))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/')
def home():
    result = db.session.execute(db.select(BlogPost).order_by(BlogPost.id.desc()).limit(5))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)

@app.route('/all-posts')
def show_all_posts():
    # Get the 'page' query param from URL, default to 1
    page = request.args.get('page', 1, type=int)
    per_page = 1
    
    # Select all posts, ordered by newest first (using ID)
    # db.paginate automatically handles the slicing
    pagination = db.paginate(
        db.select(BlogPost).order_by(BlogPost.id.desc()),
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    return render_template("all-posts.html", pagination=pagination)

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
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
            posts=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=form)


@app.route("/new-post", methods=["GET", "POST"])
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
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_and_author_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@login_required
@admin_and_author_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/about")
def about():
    # Fetch all users where is_admin is True
    result = db.session.execute(db.select(User).where(User.is_admin == True))
    admins = result.scalars().all()
    return render_template("about.html", admins=admins)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    # 1. Handle POST request (User submitting form)
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("You must be logged in to send a message.", "danger")
            return redirect(url_for("login"))

        new_message = Message(
            name=current_user.name,       # Auto-fill from logged-in user
            email=current_user.email,     # Auto-fill from logged-in user
            phone=request.form.get("phone"),
            text=request.form.get("message"),
            date=datetime.now().strftime("%B %d, %Y, %H:%M")  # e.g. January 01, 2026, 12:00
        )
        db.session.add(new_message)
        db.session.commit()

        flash("Message sent! The admin will review it shortly.", "success")
        return redirect(url_for("contact"))

    # 2. Handle GET request (Show the page)
    return render_template("contact.html")

@app.route("/profile/<int:user_id>")
def profile(user_id):
    user = db.get_or_404(User, user_id)
    
    return render_template("profile.html", user=user)



@app.route("/edit-profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    form = EditProfileForm(obj=current_user)

    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.bio = form.bio.data
        current_user.linkedin_url = form.linkedin_url.data
        current_user.github_url = form.github_url.data
        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile', user_id=current_user.id))
    else:
        flash("Enter valid URL!", "unsuccessful")
        pass
    return render_template("edit-profile.html", form=form)

@app.route("/admin")
@login_required
@admin_only
def admin_dashboard():
    posts = db.session.execute(db.select(BlogPost)).scalars().all()
    users = db.session.execute(db.select(User)).scalars().all()
    admins = db.session.execute(db.select(User).where(
        User.is_admin == True)).scalars().all()
    return render_template(
        "admin.html",
        posts=posts,
        users=users,
        admins=admins,
        total_posts=len(posts),
        total_users=len(users)
    )


"""-----------------------------------ERROR HANDLER----------------------------"""


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(debug=False)
