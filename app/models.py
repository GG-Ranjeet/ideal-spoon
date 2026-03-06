from . import db
from flask_login import UserMixin
from datetime import datetime

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
    date = db.DateTimeField(required=True, max_length=250)
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
