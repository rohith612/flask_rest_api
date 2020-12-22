from flask import request, jsonify
import jwt
from .models import User
from .config import Config
from functools import wraps


# token verification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'X-access-token' in request.headers:
            token = request.headers['X-access-token']

        if not token:
            return jsonify({"message": "Token is missing...!"})

        try:
            data = jwt.decode(token, Config.SECRET_KEY)
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"message": "Token is invalid!"})

        return f(current_user, *args, **kwargs)

    return decorated

