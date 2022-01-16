
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_restx import Api, Resource, reqparse


app = Flask(__name__)
api = Api(app)

api.config['SECRET_KEY'] = 'SI03152398058'

api.config['SQLALCHEMY_DATABASE_URI'] = 'products.db'
api.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

database= SQLAlchemy(api)
parser = reqparse.RequestParser()



class User(database.Model):
	id = database.Column(database.Integer, primary_key = True)
	public_id = database.Column(database.String(50), unique = True)
	name = database.Column(database.String(100))
	email = database.Column(database.String(70), unique = True)
	password = database.Column(database.String(80))

@api.route('/ home')




def get_home():
	return render_template('home.html',home )


@api.route('/login')


def get_login():
			return render_template('login.html', login)



def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		# jwt is passed in the request header
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		# return 401 if token is not passed
		if not token:
			return jsonify({'message' : 'Token is missing !!'}), 401

		try:
			# decoding the payload to fetch the stored details
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query\
				.filter_by(public_id = data['public_id'])\
				.first()
		except:
			return jsonify({
				'message' : 'Token is invalid !!'
			}), 401
		# returns the current logged in users contex to the routes
		return f(current_user, *args, **kwargs)

	return decorated


@api.route('/user')
@token_required
def get_all_users(current_user):

	users = User.query.all()

	output = []
	for user in users:

		output.append({
			'public_id': user.public_id,
			'name' : user.name,
			'email' : user.email
		})

	return jsonify({'users': output},user)



@api.route('/login')
def login():

	auth = request.form

	if not auth or not auth.get('email') or not auth.get('password'):

		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
		)

	user = User.query\
		.filter_by(email = auth.get('email'))\
		.first()

	if not user:

		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
		)

	if check_password_hash(user.password, auth.get('password')):
		# generates the JWT Token
		token = jwt.encode({
			'public_id': user.public_id,
			'exp' : datetime.utcnow() + timedelta(minutes = 30)
		}, api.config['SECRET_KEY'])

		return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)

	return make_response(
		'Could not verify',
		403,
		{'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
	)


@api.route('/signup /<string:id>')
def signup():
	@api.doc(parser=parser)

	args = parser.parse_args()
	post_var1 = args['name']
	post_var2 = args['email']
	post_var3 = args['password']

	user = User.query\
		.filter_by(email = email)\
		.first()
	if not user:
		# database ORM object
		user = User(
			public_id = str(uuid.uuid4()),
			name = name,
			email = email,
			password = generate_password_hash(password)
		)
		# insert user
		database.session.add(user)
		database.session.commit()

		return make_response('Signup.html', + post_var1,+ post_var2,+post_var3)
	else:

		return make_response('User already exists. Please Log in.', 202)

if __name__ == "__main__":
	app.run()



