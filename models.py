from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

# Initialize db only here, don't re-initialize it elsewhere
db = SQLAlchemy()

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Added email field
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # New field to indicate if user is admin
    banned = db.Column(db.Boolean, default=False)  # Field to track banned users
    comments = db.relationship('Comment', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


# Define the Topic model
class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    comments = db.relationship('Comment', backref='topic', lazy=True)


# Define the Comment model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    sentiment = db.Column(db.String(20))
    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Add foreign key linking to User

