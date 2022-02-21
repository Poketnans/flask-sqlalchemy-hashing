from dataclasses import dataclass
import email
from http import HTTPStatus
import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Query
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config['JSON_SORT_KEYS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


@dataclass
class UserModel(db.Model):

    id: int
    name: str
    email: str

    __tablename__ = 'usuarios'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)

    password_hash = db.Column(db.String, nullable=True)

    @property
    def password(self):
        raise AttributeError('Password cannot be accessed!')

    @password.setter
    def password(self, password_to_hash):
        self.password_hash = generate_password_hash(password_to_hash)

    def verify_password(self, password_to_compare):
        return check_password_hash(self.password_hash, password_to_compare)


db.create_all()


@app.post('/users')
def create_user():
    payload = request.json

    '''
        Payload template:
        {
         "name": "John Doe",
         "email": "john@doe.email",
         "password": "strong_password"   
        }
    '''

    new_user = UserModel(**payload)

    db.session.add(new_user)
    db.session.commit()

    return jsonify(new_user), HTTPStatus.CREATED


@app.post('/login')
def login():
    payload = request.json

    '''
        Payload template:
        {
         "email": "john@doe.email",
         "password": "strong_password"   
        }
    '''

    base_query: Query = UserModel.query

    user: UserModel = base_query.filter_by(email=payload['email']).first()

    if not user:
        resp = jsonify({'error': 'email or password incorrect.'})
        return resp, HTTPStatus.UNAUTHORIZED

    match = user.verify_password(payload['password'])

    if not match:
        resp = jsonify({'error': 'email or password incorrect.'})
        return resp, HTTPStatus.UNAUTHORIZED

    return jsonify(user), HTTPStatus.OK
