import os
from flask import Flask, render_template, request, redirect, send_from_directory, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from functools import wraps
from flask_bootstrap import Bootstrap
from bson.objectid import ObjectId
from flask import request
import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
import joblib
from sklearn.pipeline import make_pipeline

# إعداد التطبيق
app = Flask(__name__)
Bootstrap(app)
app.secret_key = 'Bahah@MedSalik@2024'  # ضع هنا مفتاحًا سريًا قويًا

# إعداد اتصال MongoDB
client = MongoClient('localhost', 27017)
db = client['ProjetNoSql']  # استخدم قاعدة البيانات الخاصة بك
users_collection = db['users']
files_collection = db['files']


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
    if session.get('role') == 1:
        return redirect(url_for('home_admin'))
    else:
        return redirect(url_for('home_user'))

# صفحة المدير
@app.route('/home-admin')
@login_required
def home_admin():
    # التحقق من دخول المدير فقط
    if session.get('role') != 1:
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    # الحصول على جميع الملفات من قاعدة البيانات
    files = list(files_collection.find())
    # استخدام الدالة المساعدة لقص أسماء الملفات الطويلة
    for file in files:
        file['short_name'] = shorten_filename(file['nom'])

    # تصنيف الملفات حسب التصنيف
    categorized_files = {}
    for file in files:
        classification = file.get('classification', 'Uncategorized')
        if classification not in categorized_files:
            categorized_files[classification] = []
        categorized_files[classification].append(file)

    return render_template('home_admin.html', categorized_files=categorized_files)

# صفحة المستخدم العادي
@app.route('/home-user')
@login_required
def home_user():
    return render_template('home_user.html')

# تسجيل الدخول
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        if session.get('role') == 1:
            return redirect(url_for('home_admin'))
        else:
            return redirect(url_for('home_user'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = users_collection.find_one({"email": form.email.data})
        if user and check_password_hash(user['password'], form.password.data):
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 1:
                return redirect(url_for('home_admin'))
            else:
                return redirect(url_for('home_user'))
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
                "role": 0  # تعيين القيمة الافتراضية للحقل role إلى 0
            })
            flash('Registered successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists!', 'danger')
    return render_template('register.html', form=form)

# إدارة المستخدمين
@app.route('/manage-users')
@login_required
def manage_users():
    if session.get('role') != 1:
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    users = users_collection.find()
    return render_template('manage_users.html', users=users)

# حذف المستخدم
@app.route('/delete-user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if session.get('role') != 1:
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    users_collection.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

# تغيير دور المستخدم
@app.route('/toggle-role/<user_id>', methods=['POST'])
@login_required
def toggle_role(user_id):
    if session.get('role') != 1:
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    user = users_collection.find_one({'_id': ObjectId(user_id)})
    new_role = 0 if user['role'] == 1 else 1
    users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': {'role': new_role}})
    flash('User role updated successfully!', 'success')
    return redirect(url_for('manage_users'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = file.filename
            filetype = file.content_type
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # حفظ الملف في المجلد المحدد
            file.save(filepath)
            
            # قراءة محتوى الملف وتحليله
            content = file.read().decode('utf-8')
            classification = classify_content(content)
            
            # تخزين معلومات الملف في قاعدة البيانات
            files_collection.insert_one({
                "nom": filename,
                "type": filetype,
                "chemin": filepath,
                "date_telechargement": datetime.datetime.now(),
                "uploaded_by": session['username'],
                "classification": classification
            })
            
            flash('File uploaded and classified successfully!', 'success')
            return redirect(url_for('upload_file'))
        else:
            flash('No file uploaded!', 'danger')
    return render_template('upload.html')




# مجلد لتخزين الملفات المرفوعة
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)




@app.route('/files')
@login_required
def list_files():
    # التحقق من صلاحية المستخدم
    # if session.get('role') != 'admin':
    #     flash('Unauthorized access!', 'danger')
    #     return redirect(url_for('home'))

    # الحصول على معلومات البحث من الطلب
    query = request.args.get('query', '')

    # البحث عن الملفات بناءً على اسم الملف
    if query:
        files = list(files_collection.find({"nom": {"$regex": query, "$options": "i"}}))
    else:
        files = list(files_collection.find())

    # استخدام الدالة المساعدة لقص أسماء الملفات الطويلة
    for file in files:
        file['short_name'] = shorten_filename(file['nom'])

    return render_template('files.html', files=files)

def shorten_filename(filename, max_length=14):
    if len(filename) > max_length:
        return filename[:max_length] + '...'
    return filename


@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    # التحقق من صلاحية المستخدم
    # if session.get('role') != 'admin':
    #     flash('Unauthorized access!', 'danger')
    #     return redirect(url_for('home'))

    # جلب معلومات الملف من قاعدة البيانات
    file = files_collection.find_one({"_id": ObjectId(file_id)})

    if file:
        return send_from_directory(app.config['UPLOAD_FOLDER'], file['nom'])
    else:
        flash('File not found!', 'danger')
        return redirect(url_for('list_files'))

@app.route('/delete/<file_id>')
@login_required
def delete_file(file_id):
    # التحقق من صلاحية المستخدم
    if session.get('role') != 1:
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    # جلب معلومات الملف من قاعدة البيانات
    file = files_collection.find_one({"_id": ObjectId(file_id)})

    if file:
        try:
            os.remove(file['chemin'])
            files_collection.delete_one({"_id": ObjectId(file_id)})
            flash('File deleted successfully!', 'success')
        except OSError as e:
            flash(f'Error deleting file: {e}', 'danger')
    else:
        flash('File not found!', 'danger')

    return redirect(url_for('list_files'))

# تدريب نموذج مطور لتصنيف النصوص باستخدام RandomForestClassifier
def train_model():
    # مجموعة بيانات مثال
    texts = ["CV , Societe ,Developper , travail","Ceci est un document sur le sport","Messi Ronaldo footbol","CV du Bahah Mbeirik","Ceci est un document sur le TD", "Le sport est amusant","رابطة البشائر للثقافة و التنمية","Ceci est un document sur le Cours", "La politique peut être compliquée", "Ceci est TD du , Td du"]
    labels = ["Education","sports","sports", "Education","travail", "sports","travail","Education", "politiques","Education"]

    model = make_pipeline(TfidfVectorizer(), RandomForestClassifier())
    model.fit(texts, labels)

    # حفظ النموذج والمحول
    joblib.dump(model.named_steps['tfidfvectorizer'], 'vectorizer.joblib')
    joblib.dump(model.named_steps['randomforestclassifier'], 'classifier.joblib')

train_model()

# نموذج بسيط لتصنيف النصوص
def load_model():
    vectorizer = joblib.load('vectorizer.joblib')
    model = joblib.load('classifier.joblib')
    return vectorizer, model

vectorizer, model = load_model()

def classify_content(content):
    X = vectorizer.transform([content])
    prediction = model.predict(X)
    return prediction[0]


# تسجيل الخروج
@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
