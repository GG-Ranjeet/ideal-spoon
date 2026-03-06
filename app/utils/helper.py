import hashlib

def gravatar(email, size=100, rating='g', default='retro', force_default=False):
    email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{email_hash}?s={size}&d={default}&r={rating}"