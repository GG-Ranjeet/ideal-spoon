from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, URL, Optional, Email
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class EditProfileForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    bio = TextAreaField("Bio (Tell us about yourself)")
    linkedin_url = StringField("LinkedIn URL", validators=[Optional(), URL()])
    github_url = StringField("GitHub URL", validators=[Optional(), URL()])
    submit = SubmitField("Update Profile")

# Creates a RegisterForm to register new users
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])    
    submit = SubmitField("Register")

# Creates a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])    
    submit = SubmitField("Login")

# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit")

class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email Address", validators=[DataRequired()])
    phone = StringField("Phone Number")
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Send Message")