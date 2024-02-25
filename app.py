import os
import cryptography
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_migrate import Migrate
from cryptography.fernet import Fernet
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # database named 'site.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # secret key for security
db = SQLAlchemy(app) # database
bcrypt = Bcrypt(app) # bcrypt for password hashing
login_manager = LoginManager(app) # login manager
migrate = Migrate(app, db) # migration


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True) # unique identifier for each user
    email = db.Column(db.String(120), unique=True, nullable=False) # email
    password = db.Column(db.String(60), nullable=False) # password
    cipher_suite_key = db.Column(db.String(255), nullable=False) # Fernet key for the user
    cipher_suite = relationship("CipherSuite", uselist=False, back_populates="user")  # relationship

    def is_active(self):  # make sure user is active, allowing them to login
        return True

    def is_authenticated(self):  # allow login if authentication is successful
        return True

    def is_anonymous(self):  # make sure the user is not an anon
        return False

    def get_id(self):  # use to load login info
        return str(self.id)


class CipherSuite(db.Model): # CipherSuite model
    id = db.Column(db.Integer, primary_key=True) # unique identifier for each cipher suite
    key = db.Column(db.String(255), nullable=False) # Fernet key
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # user who owns this cipher suite
    user = relationship("User", back_populates="cipher_suite")  # relationship


class UserCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # unique identifier for each credential
    website = db.Column(db.String(255), nullable=False)  # website name
    username = db.Column(db.String(255), nullable=False)  # username
    password = db.Column(db.String(255), nullable=False)  # pass
    url = db.Column(db.String(255))  # url
    folder = db.Column(db.String(255)) # folder
    notes = db.Column(db.Text) # notes
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # user who owns this credential

    def __repr__(self):  # use in case of needing to tracking obj
        return f"UserCredential(id={self.id}, website={self.website}, username={self.username})"


@app.route('/add_credentials_page', methods=['GET', 'POST'])
@login_required  # make sure logged in
def add_credentials():
    if request.method == 'POST':  # if POST
        website = request.form['name']
        folder = request.form['folder']
        url = request.form['url']
        username = request.form['username']
        password = request.form['password']
        notes = request.form['notes']
        user_key = User.query.filter_by(id=current_user.id).first().cipher_suite_key # get user key
        cipher_suite = Fernet(user_key) # create a Fernet cipher suite
        encrypted_password = cipher_suite.encrypt(password.encode()).decode('utf-8') # encrypt the password
        new_credential = UserCredential( # create a new credential
            website=website,
            folder=folder,
            url=url,
            username=username,
            password=encrypted_password,
            notes=notes,
            user_id=current_user.id
        )

        db.session.add(new_credential)  # add credential to the database
        db.session.commit()  # commit the change

        return redirect(url_for('vault'))

    return render_template('add_credentials.html')


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/get_credential/<int:credential_id>', methods=['GET']) # get credential by id
@login_required  # make sure logged in
def get_credential(credential_id):
    credential = UserCredential.query.filter_by(id=credential_id,
                                                user_id=current_user.id).first()  # find the credential with id
    if credential:  # if true
        return {
            'website': credential.website,
            'username': credential.username,
            'password': credential.password,
            'notes': credential.notes
        }
    else:
        return {'error': 'Credential not found'}, 404  # if not found return 404


@app.route('/update_credential/<int:credential_id>', methods=['POST'])
@login_required
def update_credential(credential_id):
    credential = UserCredential.query.filter_by(id=credential_id, user_id=current_user.id).first() # find the credential
    if credential:
        data = request.json  # get data from request
        try:
            credential.website = data.get('website', credential.website)
            credential.url = data.get('url', credential.url)
            credential.username = data.get('username', credential.username)
            credential.notes = data.get('notes', credential.notes)

            # Update password only if it's present in the request data
            if 'password' in data:
                user_key = User.query.filter_by(id=current_user.id).first().cipher_suite_key
                cipher_suite = Fernet(user_key)
                encrypted_password = cipher_suite.encrypt(data['password'].encode()).decode('utf-8')
                credential.password = encrypted_password

            db.session.commit()  # Commit changes to the database
            return jsonify({'message': 'Credential updated successfully'})
        except SQLAlchemyError as e:
            db.session.rollback()  # Rollback changes in case of error
            print("Error updating credential:", str(e))
            return jsonify({'error': 'Error updating credential'}), 500
    else:
        return jsonify({'error': 'Credential not found'}), 404


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST']) # sign up
def signup():
    if request.method == 'POST':
        email = request.form['signupEmail']
        password = request.form['signupPassword']
        confirm_password = request.form['confirmPassword']

        existing_user = User.query.filter_by(email=email).first()  # check if email already exist

        if existing_user:  # if exist
            return render_template('signup.html', error='Email already exists. Please choose a different one.')

        if password != confirm_password:  # if password does not match
            return render_template('signup.html', error='Passwords do not match')

        # Generate a new Fernet key
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)

        # Hash the password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new user entry in the database
        user = User(email=email, password=hashed_password, cipher_suite_key=key.decode('utf-8'))
        db.session.add(user)
        db.session.commit()

        # Create a new CipherSuite entry in the database associated with the user
        cipher_entry = CipherSuite(key=key.decode('utf-8'), user_id=user.id)
        db.session.add(cipher_entry)
        db.session.commit()

        return redirect(url_for('home'))

    return render_template('signup.html')


@app.route('/signin', methods=['GET', 'POST']) # sign in
def signin():
    if request.method == 'POST':
        email = request.form['signinEmail'] # get email
        password = request.form['signinPassword'] # get password

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):  # check if the user and password correct
            login_user(user)
            return redirect(url_for('vault')) # redirect to vault

        return render_template('signin.html', error='Username or password is incorrect. Please try again.')

    return render_template('signin.html')


import traceback
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)  # Set logging level to DEBUG


@app.route('/decrypt_password', methods=['POST'])
def decrypt_password():
    try:
        encrypted_password = request.json.get('encrypted_password').encode().decode('utf-8')  # get encrypted pass
        user_key = User.query.filter_by(id=current_user.id).first().cipher_suite_key
        cipher_suite = Fernet(user_key)
        decrypted_password = cipher_suite.decrypt(encrypted_password).decode('utf-8')
        return jsonify({'decrypted_password': decrypted_password}), 200  # return decode pass to vault
    except cryptography.fernet.InvalidToken as e:
        print(e)
        error_message = 'Invalid or corrupted encrypted password. Please try again.'
        logging.error(error_message)  # log
        return jsonify({'error': error_message}), 500
    except cryptography.exceptions.InvalidSignature:
        error_message = 'Signature verification failed. The encrypted password may be invalid or corrupted.'
        logging.error(error_message)  # log
        return jsonify({'error': error_message}), 500
    except Exception as e:
        error_message = 'An unexpected error occurred: {}'.format(e)
        traceback_message = traceback.format_exc()
        logging.error(error_message)  # log
        logging.error(traceback_message)  # log
        return jsonify({'error': error_message, 'traceback': traceback_message}), 500


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
    return render_template('note.html')


@app.route('/delete_credential/<int:credential_id>', methods=['DELETE'])
@login_required
def delete_credential(credential_id):
    credential = UserCredential.query.filter_by(id=credential_id, user_id=current_user.id).first()
    if credential:
        db.session.delete(credential)
        db.session.commit()
        return jsonify({'message': 'Credential deleted successfully'}), 200
    else:
        return jsonify({'error': 'Credential not found'}), 404


if __name__ == '__main__':
    app.run(debug=True, port=2382, host="0.0.0.0")

# todo: random pass generator
