from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from functools import wraps
from flask_bootstrap import Bootstrap

# إعداد التطبيق
app = Flask(__name__)
Bootstrap(app)
app.secret_key = 'Bahah@MedSalik@2024'  # ضع هنا مفتاحًا سريًا قويًا

# إعداد اتصال MongoDB
client = MongoClient('localhost', 27017)
db = client['ProjetNoSql']  # استخدم قاعدة البيانات الخاصة بك
users_collection = db['users']

# تعريف نموذج تسجيل الدخول
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(min=6, max=40)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=25)])
    submit = SubmitField('Login')


# تعريف نموذج التسجيل
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
    email = StringField('Email', validators=[DataRequired(), Length(min=6, max=40)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=25)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = StringField('Role', validators=[DataRequired(), Length(min=1, max=1)])
    submit = SubmitField('Register')


# ديكورتر للتحقق من تسجيل الدخول
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# الصفحة الرئيسية
@app.route('/')
@login_required
def home():
    return render_template('home.html')

# تسجيل الدخول
@app.route('/login', methods=['GET', 'POST'])
def login():
    # التحقق مما إذا كان المستخدم مسجل الدخول بالفعل
    if 'username' in session:
        # flash('You are already logged in!', 'info')
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = users_collection.find_one({"email": form.email.data})
        if user and check_password_hash(user['password'], form.password.data):
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)


# التسجيل
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = users_collection.find_one({"email": form.email.data})
        if existing_user is None:
            hash_pass = generate_password_hash(form.password.data)
            users_collection.insert_one({
                "username": form.username.data,
                "email": form.email.data,
                "password": hash_pass,
                "role": form.role.data
            })
            flash('Registered successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists!', 'danger')
    return render_template('register.html', form=form)


# تسجيل الخروج
@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
