from flask import request, jsonify, make_response, Blueprint
import uuid
import datetime

from rest_api.models import Todo
from rest_api.config import Config
from rest_api.utils import token_required
from rest_api.models import db

todos = Blueprint('todos', __name__)


@todos.route('/todo', methods=['GET'])
@token_required
def get_all_todo(current_user):
    pass


@todos.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    pass


@todos.route('/todo/<id>', methods=['PUT'])
@token_required
def update_todo(current_user, id):
    pass


@todos.route('/todo/<id>', methods=['GET'])
@token_required
def get_one_todo(current_user, id):
    pass


@todos.route('/todo/<id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, id):
    pass

