import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class UserCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"UserCredential(id={self.id}, website={self.website}, username={self.username})"


# Create the tables before running the app
with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['signupEmail']
        password = request.form['signupPassword']
        confirm_password = request.form['confirmPassword']

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            return render_template('signup.html', error='Email already exists. Please choose a different one.')

        if password != confirm_password:
            return render_template('signup.html', error='Passwords do not match')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('home'))

    return render_template('signup.html')


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['signinEmail']
        password = request.form['signinPassword']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('vault'))

        return render_template('signin.html', error='Username or password is incorrect. Please try again.')

    return render_template('signin.html')


@app.route('/vault')
@login_required
def vault():
    user_credentials = UserCredential.query.filter_by(user_id=current_user.id).all()
    return render_template('vault.html', user_credentials=user_credentials)


@app.route('/add_credentials_page')
@login_required
def add_credentials_page():
    return render_template('add_credentials.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico')


@app.route('/password')
def password():
    render_template('password.html')


@app.route('/note')
def note():
    render_template('note.html')


if __name__ == '__main__':
    app.run(debug=True, port=2382)

# todo: random pass generator
