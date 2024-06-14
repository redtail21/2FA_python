from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from forms import LoginForm, RegistrationForm, TwoFactorForm
import pyotp
import qrcode
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Ensure the directory for storing QR codes exists
if not os.path.exists('static/qrcodes'):
    os.makedirs('static/qrcodes')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please log in.', 'danger')
            return redirect(url_for('login'))
        
        otp_secret = pyotp.random_base32()
        user = User(username=form.username.data, password=form.password.data, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Account created successfully', 'success')
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for('validate_2fa'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/two_factor_setup')
@login_required
def two_factor_setup():
    user = current_user
    otp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(name=user.username, issuer_name='YourApp')
    qr = qrcode.make(otp_uri)
    qr_filename = f'{user.username}.png'
    qr_path = os.path.join('static/qrcodes', qr_filename)
    qr.save(qr_path)
    return render_template('2fa.html', qr_path=f'qrcodes/{qr_filename}')

@app.route('/validate_2fa', methods=['GET', 'POST'])
@login_required
def validate_2fa():
    form = TwoFactorForm()
    if form.validate_on_submit():
        user = current_user
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(form.token.data):
            flash('Two-factor authentication successful', 'success')
            return redirect(url_for('protected'))
        else:
            flash('Invalid 2FA token', 'danger')
    return render_template('validate_2fa.html', form=form)

@app.route('/protected')
@login_required
def protected():
    return 'Logged in successfully with 2FA!'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
