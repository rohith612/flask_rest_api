from flask import request, jsonify, make_response, Blueprint
import uuid
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from rest_api.models import User
from rest_api import db
from rest_api.config import Config
from rest_api.utils import token_required
from rest_api.models import db

users = Blueprint('users', __name__)


@users.route('/create', methods=['GET'])
def create_db():
    db.create_all()
    return jsonify({'massage': 'Db created!'})


# app routes
# register new user
# # @token_required
@users.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(
        data['password'],
        method='sha256'
    )

    new_user = User(
        public_id=str(uuid.uuid4()),
        name=data['name'],
        password=hashed_password,
        admin=False
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'massage': 'New user created!'})


# list all users
@users.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


# get individual users
@users.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'users': user_data})


# update user data
@users.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user promoted!'})


# delete existing user details
@users.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete()
    db.session.commit()

    return jsonify({'message': 'The user deleted!'})


# login users
@users.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id,
             'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            Config.SECRET_KEY
        )

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


