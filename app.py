from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
from functools import wraps
from users import authenticate  # Corrected import statement

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ByYM000OLlMQG6VVVp1OH7Xzyr7gHuw1qvUC5dcGt3SNM'
CORS(app)  # Add this line to enable CORS for all routes

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-tokens')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            print(token)
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
            current_role = data['role']
        except Exception as e:
            print("Error " + e)
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, current_role, *args, **kwargs)
    return decorated

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, current_role, *args, **kwargs):
            if current_role != required_role:
                return jsonify({'message': 'You do not have access to this resource!'}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = authenticate(username, password)
    if not user:
        return jsonify({'message': 'Invalid credentials!'}), 401

    token = jwt.encode({
        'username': user['username'],
        'role': user['role'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token})

@app.route('/admin', methods=['GET'])
@token_required
@role_required('admin')
def admin(current_user):
    return jsonify({'message': f'Welcome {current_user}, you have admin access!'})

@app.route('/user', methods=['GET'])
@token_required
@role_required('user')
def user(current_user):
    return jsonify({'message': f'Welcome {current_user}, you have user access!'})

@app.route('/guest', methods=['GET'])
@token_required
@role_required('guest')
def guest(current_user):
    return jsonify({'message': f'Welcome {current_user}, you have guest access!'})

if __name__ == '__main__':
    app.run(debug=True)
