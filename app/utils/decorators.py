from functools import wraps
from flask import abort
from flask_login import current_user
from app.models import BlogPost

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

