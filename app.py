from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from webforms import UserForm,LoginForm ,PasswordForm
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = "my super secret key that no one is supposed to know"
app.config['WTF_CSRF_ENABLED'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)


@app.route('/hello', methods=['GET'])
def hello():
    return {'name':'mini'}

@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    form = UserForm()
    if request.method == 'POST':
        form = UserForm(data=request.json)
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # Hash the password
            hashed_pw = generate_password_hash(form.password_hash.data, method="pbkdf2:sha256")
            new_user = Users(
                username=form.username.data,
                name=form.name.data,
                email=form.email.data,
                #favorite_color=form.favorite_color.data,
                password_hash=hashed_pw
            )
            db.session.add(new_user)
            db.session.commit()
            return {'res': 'User added successfully'}
        else:
            return {'error': 'User with this email already exists'}
    return {'error': 'Form validation failed'}


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        form = LoginForm(data=request.json)
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # Check the hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                return {'res': 'Logging successful'}
            else:
                return {'error': 'Wrong Password - Try Again!'}
        else:
            return {'error': "That User Doesn't Exist! Try Again..."}
    return {'error': 'Form validation failed'}


	


class Users(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable=False, unique=True)
	name = db.Column(db.String(200), nullable=False)
	email = db.Column(db.String(120), nullable=False, unique=True)
	password_hash = db.Column(db.String(128))

if __name__=='__main__':
    app.run(debug=True)