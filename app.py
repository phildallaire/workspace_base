from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from datetime import timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=True)
    provider = db.Column(db.String(50), nullable=True)
    provider_id = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

with app.app_context():
    db.create_all()

@app.route('/signup/email', methods=['POST'])
def signup_email():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201
@app.route('/signup/facebook', methods=['POST'])
def signup_facebook():
    data = request.get_json()
    access_token = data.get('accessToken')
    if not access_token:
        return jsonify({'error': 'Access token is required'}), 400
    # Here you would verify the access token with Facebook's API
    # For simplicity, we'll assume the token is valid and extract a user ID
    provider_id = 'facebook_user_id'  # This should be obtained from Facebook's API
    if User.query.filter_by(provider='facebook', provider_id=provider_id).first():
        return jsonify({'error': 'User already exists'}), 400
    new_user = User(email=None, password_hash=None, provider='facebook', provider_id=provider_id)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/signup/apple', methods=['POST'])
def signup_apple():
    data = request.get_json()
    identity_token = data.get('identityToken')
    if not identity_token:
        return jsonify({'error': 'Identity token is required'}), 400
    # Here you would verify the identity token with Apple's API
    # For simplicity, we'll assume the token is valid and extract a user ID
    provider_id = 'apple_user_id'  # This should be obtained from Apple's API
    if User.query.filter_by(provider='apple', provider_id=provider_id).first():
        return jsonify({'error': 'User already exists'}), 400
    new_user = User(email=None, password_hash=None, provider='apple', provider_id=provider_id)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/signup/google', methods=['POST'])
def signup_google():
    data = request.get_json()
    id_token = data.get('idToken')
    if not id_token:
        return jsonify({'error': 'ID token is required'}), 400
    # Here you would verify the ID token with Google's API
    # For simplicity, we'll assume the token is valid and extract a user ID
    provider_id = 'google_user_id'  # This should be obtained from Google's API
    if User.query.filter_by(provider='google', provider_id=provider_id).first():
        return jsonify({'error': 'User already exists'}), 400
    new_user = User(email=None, password_hash=None, provider='google', provider_id=provider_id)
    db.session.add(new_user)
    db.session.commit()
@app.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({'error': 'Verification token is required'}), 400
    # Here you would verify the token
    # For simplicity, we'll assume the token is valid and extract a user ID
    user_id = 'user_id_from_token'  # This should be obtained from the token
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Invalid token'}), 400
    # Mark the user as verified (this would require an additional field in the User model)
    return jsonify({'message': 'Email verified successfully'}), 200

@app.route('/login/email', methods=['POST'])
def login_email():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid email or password'}), 401
    access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=1))
    return jsonify({'access_token': access_token}), 200

@app.route('/login/facebook', methods=['POST'])
def login_facebook():
    data = request.get_json()
    access_token = data.get('accessToken')
    if not access_token:
        return jsonify({'error': 'Access token is required'}), 400
    # Here you would verify the access token with Facebook's API
    # For simplicity, we'll assume the token is valid and extract a user ID
    provider_id = 'facebook_user_id'  # This should be obtained from Facebook's API
    user = User.query.filter_by(provider='facebook', provider_id=provider_id).first()
    if not user:
        return jsonify({'error': 'Invalid access token'}), 401
    access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=1))
    return jsonify({'access_token': access_token}), 200

@app.route('/login/apple', methods=['POST'])
def login_apple():
    data = request.get_json()
    identity_token = data.get('identityToken')
    if not identity_token:
        return jsonify({'error': 'Identity token is required'}), 400
    # Here you would verify the identity token with Apple's API
    # For simplicity, we'll assume the token is valid and extract a user ID
    provider_id = 'apple_user_id'  # This should be obtained from Apple's API
    user = User.query.filter_by(provider='apple', provider_id=provider_id).first()
    if not user:
        return jsonify({'error': 'Invalid identity token'}), 401
    access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=1))
    return jsonify({'access_token': access_token}), 200

@app.route('/login/google', methods=['POST'])
def login_google():
    data = request.get_json()
    id_token = data.get('idToken')
    if not id_token:
        return jsonify({'error': 'ID token is required'}), 400
    # Here you would verify the ID token with Google's API
    # For simplicity, we'll assume the token is valid and extract a user ID
    provider_id = 'google_user_id'  # This should be obtained from Google's API
    user = User.query.filter_by(provider='google', provider_id=provider_id).first()
    if not user:
        return jsonify({'error': 'Invalid ID token'}), 401
    access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=1))
    return jsonify({'access_token': access_token}), 200

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Invalid email'}), 400
    # Here you would generate a reset token and send it via email
    reset_token = 'reset_token'  # This should be a secure token
    return jsonify({'message': 'Password reset email sent'}), 200

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('newPassword')
    if not token or not new_password:
        return jsonify({'error': 'Token and new password are required'}), 400
    # Here you would verify the token
    # For simplicity, we'll assume the token is valid and extract a user ID
    user_id = 'user_id_from_token'  # This should be obtained from the token
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Invalid token'}), 400
    user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()
    return jsonify({'message': 'Password reset successfully'}), 200

@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.get_json()
    contact = data.get('contact')
    if not contact:
        return jsonify({'error': 'Contact is required'}), 400
    # Here you would generate an OTP and send it via email or SMS
    otp = '123456'  # This should be a secure OTP
    return jsonify({'message': 'OTP sent'}), 200

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    otp = data.get('otp')
    contact = data.get('contact')
    if not otp or not contact:
        return jsonify({'error': 'OTP and contact are required'}), 400
    # Here you would verify the OTP
    # For simplicity, we'll assume the OTP is valid
    return jsonify({'message': 'OTP verified successfully'}), 200

if __name__ == '__main__':
    app.run(port=5001)
