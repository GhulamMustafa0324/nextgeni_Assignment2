from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError  
import os

load_dotenv()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=False, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class BlogPost(db.Model):
    __tablename__ = 'blog_posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, nullable=False)  # To associate the comment with a blog post
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# Create tables if they don't exist
with app.app_context():
    db.create_all()

def create_token(user_id):
    payload = {'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403

        try:
            token = token.split("Bearer ")[1]  # Remove 'Bearer ' from the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 403

        return f(current_user_id, *args, **kwargs)

    return decorated


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'All fields are required'}), 400

    try:
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except IntegrityError:  # Handle duplicate email with IntegrityError
        db.session.rollback()
        return jsonify({'message': 'Email already exists. Registration failed'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email, password=password).first()

    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    token = create_token(user.id)

    return jsonify({'token': token}), 200

@app.route('/create_post', methods=['POST'])
@token_required
def create_post(current_user_id):
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')

    if not title or not content:
        return jsonify({'message': 'Title and content are required'}), 400

    post = BlogPost(title=title, content=content, author=current_user_id)

    db.session.add(post)
    db.session.commit()

    return jsonify({'message': 'Blog post created successfully'}), 201



@app.route('/post_comment', methods=['POST'])
@token_required
def post_comments(current_user_id):
    data = request.get_json()
    post_id = data.get('post_id')  # The ID of the blog post you want to comment on
    content = data.get('content')

    if not post_id or not content:
        return jsonify({'message': 'Post ID and content are required'}), 400

    # Check if the specified blog post exists
    post = BlogPost.query.get(post_id)

    if not post:
        return jsonify({'message': 'Blog post does not exist'}), 404

    # Create a new comment associated with the current user
    comment = Comment(post_id=post_id, content=content, author=current_user_id)

    db.session.add(comment)
    db.session.commit()

    return jsonify({'message': 'Comment posted successfully'}), 201


if __name__ == '__main__':
    app.run(debug=True)
