from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
from functools import wraps
from users import authenticate  # Replace with your actual authentication module
from flasgger import Swagger
from users import users
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_ISSUER'] = 'your_issuer'
app.config['JWT_AUDIENCE'] = 'your_audience'
CORS(app)  # Enable CORS for all routes
swagger = Swagger(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-tokens')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms=["HS256"],
                issuer=app.config['JWT_ISSUER'],
                audience=app.config['JWT_AUDIENCE']
            )
            current_user = data['username']
            current_role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
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
    """
    User login endpoint
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
              description: The user's username
            password:
              type: string
              description: The user's password
    responses:
      200:
        description: Login successful
        schema:
          type: object
          properties:
            token:
              type: string
              description: The generated JWT token
      401:
        description: Invalid credentials
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = authenticate(username, password)
    if not user:
        return jsonify({'message': 'Invalid credentials!'}), 401

    token = jwt.encode({
        'username': user['username'],
        'role': user['role'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iss': app.config['JWT_ISSUER'],
        'aud': app.config['JWT_AUDIENCE']
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token})

@app.route('/admin', methods=['GET'])
@token_required
@role_required('admin')
def admin(current_user):
    """
    Admin access endpoint
    ---
    tags:
      - Admin
    responses:
      200:
        description: Admin access granted
        schema:
          type: object
          properties:
            message:
              type: string
    """
    return jsonify({'message': f'Welcome {current_user}, you have admin access!', 'users': users})

@app.route('/user', methods=['GET'])
@token_required
@role_required('user')
def user(current_user):
    """
    User access endpoint
    ---
    tags:
      - User
    responses:
      200:
        description: User access granted
        schema:
          type: object
          properties:
            message:
              type: string
    """
    filtered_users = {username: details for username, details in users.items() if details['role'] == 'user'}
    return jsonify({'message': f'Welcome {current_user}, you have user access!', 'users': filtered_users})

@app.route('/guest', methods=['GET'])
@token_required
@role_required('guest')
def guest(current_user):
    """
    Guest access endpoint
    ---
    tags:
      - Guest
    responses:
      200:
        description: Guest access granted
        schema:
          type: object
          properties:
            message:
              type: string
    """
    filtered_users = {username: details for username, details in users.items() if details['role'] == 'guest'}
    return jsonify({'message': f'Welcome {current_user}, you have guest access!', 'users': filtered_users})

if __name__ == '__main__':
    app.run(debug=True)
