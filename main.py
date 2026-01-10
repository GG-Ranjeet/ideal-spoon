from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_required, login_user, LoginManager, current_user, logout_user
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, LoginForm, RegisterForm, CommentForm, EditProfileForm, ContactForm
import os
import bleach
import certifi
from datetime import datetime
from dotenv import load_dotenv
from flask_mongoengine import MongoEngine
from mongoengine.errors import NotUniqueError
import hashlib

# from flask_gravatar import Gravatar
'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
# app.config['SECRET_KEY'] = 'this_is_the_test_key'
ckeditor = CKEditor(app)
Bootstrap5(app)

# Create login manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    user_id = str(user_id)
    return User.objects(pk=user_id).first()


app.config['MONGODB_SETTINGS'] = {
    'host': os.environ.get("MONGO_URI"),
    'tlsCAFile': certifi.where()
}
db = MongoEngine(app)

# db.init_app(app)


"""-----------------------------------CREATE TABLE IN DB----------------------------"""


class User(UserMixin, db.Document):
    __tablename__ = "users"
    # 1. Basic Fields
    name = db.StringField(required=True, max_length=100)
    email = db.EmailField(required=True, unique=True)
    password = db.StringField(required=True)

    # 2. New Columns (Profile Data)
    # Note: In Mongo, we don't need nullable=True. If the data isn't there, the field just isn't saved.
    bio = db.StringField() 
    linkedin_url = db.StringField(max_length=250)
    github_url = db.StringField(max_length=250)

    # 3. Roles
    is_author = db.BooleanField(default=False)
    is_admin = db.BooleanField(default=False)
    def role_names(self):
        roles = []
        if self.is_admin:
            roles.append("Admin")
        if self.is_author:
            roles.append("Author")
        return roles or ["User"]

    # Properties
    # posts = relationship("BlogPost", back_populates="author")
    # comments = relationship("Comment", back_populates="author")
    @property
    def posts(self):
        return BlogPost.objects(author=self)
    
    @property
    def comments(self):
        return Comment.objects(author=self)

class BlogPost(db.Document):
    title = db.StringField(required=True, unique=True, max_length=250)
    subtitle = db.StringField(required=True, max_length=250)
    date = db.DateTimeField(default=datetime.now())
    body = db.StringField(required=True) # No need for Text, StringField holds anything
    img_url = db.StringField(required=True, max_length=250)

    # author: Mapped[str] = mapped_column(String(250), nullable=False)
    # author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user_table.id"))
    # author = relationship("User", back_populates="posts")
    # comments = relationship("Comment", back_populates="posts")

    # Relationship: Referenced Field replaces ForeignKey
    # reverse_delete_rule=CASCADE means if User is deleted, delete their posts too.
    author = db.ReferenceField(User, reverse_delete_rule=db.CASCADE)
    
    # Simulate relationship
    @property
    def comments(self):
        return Comment.objects(parent_post=self)

# Assuming User and BlogPost are already defined or imported

class Comment(db.Document):
    # 1. No __tablename__. MongoDB uses the class name (lowercased) by default.
    #    If you want a specific name: meta = {'collection': 'comments'}
    
    # 2. Field Definitions
    text = db.StringField(required=True, max_length=1000)

    # 3. Relationships (Replacing ForeignKey & relationship)
    # This stores the User's ID in the database, but allows you to access 
    # comment.author.name in your code.
    author = db.ReferenceField('User', reverse_delete_rule=db.CASCADE)
    
    # This links to the blog post
    parent_post = db.ReferenceField('BlogPost', reverse_delete_rule=db.CASCADE)


class Message(db.Document):
    # 1. No need to define 'id'. 
    # MongoDB creates a unique '_id' automatically.
    
    name = db.StringField(required=True, max_length=100)
    email = db.EmailField(required=True, max_length=100)
    phone = db.StringField(max_length=100) # Optional field
    text = db.StringField(required=True)    # No limit, like Text
    
    # 2. Better Date Handling
    # In SQL you used String. In MongoDB, use DateTimeField for better sorting.
    # default=datetime.utcnow handles the timestamp automatically.
    date = db.DateTimeField(default=datetime.now())
    
    is_read = db.BooleanField(default=False)



"""-----------------------------------AVATAR GEN----------------------------"""
# doesnt work with flask>v3
# gravatar = Gravatar(app,
#                     size=100,
#                     rating='g',
#                     default='retro',
#                     force_default=False,
#                     force_lower=False,
#                     use_ssl=False,
#                     base_url=None)

@app.template_filter('gravatar')
def gravatar_url(email, size=100, default='identicon', rating='g'):
    url = 'https://www.gravatar.com/avatar'
    hash_value = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    return f"{url}/{hash_value}?s={size}&d={default}&r={rating}"

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
        post = BlogPost.objects.get_or_404(pk=post_id)

        # Admin can do anything
        if current_user.is_admin:
            return func(*args, **kwargs)

        # Author can edit/delete their own post
        if current_user.is_author and post.author == current_user:
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
        abort(403, description="Not authorised. 😎")
    return wrapper


"""-------------------------------------VIEWS-------------------------------"""


@app.route('/register', methods=["GET", "POST"])
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
            login_user(new_user, remember=True)
            return redirect(url_for('home'))
        except NotUniqueError:
            flash("Email already exists. Please log in.", "danger")
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
        user = User.objects(email=email).first()

        if not user:
            flash("Email does not exist. Try again.", "danger")
        elif not check_password_hash(user.password, password):
            flash("Incorrect password.", "danger")
        else:
            login_user(user, remember=True)
            return redirect(url_for("home"))
    return render_template("login.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/')
def home():
    # result = db.session.execute(db.select(BlogPost).order_by(BlogPost.id.desc()).limit(5))
    result = BlogPost.objects.order_by('-id').limit(5)
    posts = list(result)
    return render_template("index.html", all_posts=posts)

@app.route('/all-posts')
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

@app.route("/post/<post_id>", methods=["GET", "POST"])
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
            date=datetime.now()
            # .strftime("%B %d, %Y")
        )
        new_post.save()
        return redirect(url_for("home"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<post_id>", methods=["GET", "POST"])
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
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<post_id>")
@login_required
@admin_and_author_only
def delete_post(post_id):
    post_to_delete = BlogPost.objects.get_or_404(pk=post_id)
    if post_to_delete.author != current_user:
        abort(403, description="Not authorised.")

    post_to_delete.delete()
    return redirect(url_for('home'))


@app.route("/about")
def about():
    result = User.objects(is_admin=True)
    admins = list(result)
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
            date=datetime.now()  # e.g. January 01, 2026, 12:00
        )
        new_message.save()

        flash("Message sent! The admin will review it shortly.", "success")
        return redirect(url_for("contact"))

    # 2. Handle GET request (Show the page)
    return render_template("contact.html")

@app.route("/profile/<user_id>")
def profile(user_id):
    user = User.objects.get_or_404(pk=user_id)
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
        current_user.save()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile', user_id=current_user.pk))
    else:
        flash("Enter valid URL!", "unsuccessful")
        pass
    return render_template("edit-profile.html", form=form)


@app.route("/admin")
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

"""-----------------------------------ERROR HANDLER----------------------------"""


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

debugging = os.environ.get("DEBUGG")
if __name__ == "__main__":
    app.run(debug=debugging)
