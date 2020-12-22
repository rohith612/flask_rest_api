from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(60))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(60))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


