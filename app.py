import os
import secrets
import csv
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

database_url = os.environ.get('DATABASE_URL')

if database_url:
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    if database_url.startswith('postgresql://') and '+psycopg' not in database_url:
        database_url = database_url.replace('postgresql://', 'postgresql+psycopg://', 1)
    if 'sslmode' not in database_url:
        separator = '&' if '?' in database_url else '?'
        database_url += f'{separator}sslmode=require'
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300
    }
else:
    basedir = os.path.abspath(os.path.dirname(__file__))
    db_folder = os.path.join(basedir, 'instance')
    os.makedirs(db_folder, exist_ok=True)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(db_folder, "site.db")}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

basedir = os.path.abspath(os.path.dirname(__file__))
if os.environ.get('RENDER'):
    app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
    app.config['DATA_FOLDER'] = '/tmp/data'
else:
    app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
    app.config['DATA_FOLDER'] = os.path.join(basedir, 'data')

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'csv', 'xlsx'}

db = SQLAlchemy(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DATA_FOLDER'], exist_ok=True)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    files = db.relationship('File', backref='owner', lazy=True, cascade='all, delete-orphan')
    documents = db.relationship('Document', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    original_filename = db.Column(db.String(256), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    description = db.Column(db.Text)
    is_public = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'user_id': self.user_id
        }


class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category = db.Column(db.String(100))
    tags = db.Column(db.String(300))

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'user_id': self.user_id
        }


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_file_extension(filename):
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else ''


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'warning')
            return redirect(url_for('login', next=request.url))
        user = User.query.get(session['user_id'])
        if not user or not user.is_active:
            session.clear()
            flash('Сессия истекла или аккаунт деактивирован', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


def save_to_csv(filename, data, fieldnames):
    filepath = os.path.join(app.config['DATA_FOLDER'], filename)
    file_exists = os.path.exists(filepath)
    with open(filepath, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)


def log_user_action(action, username, email, **extra):
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'username': username,
        'email': email
    }
    log_entry.update(extra)
    save_to_csv('users_log.csv', log_entry, list(log_entry.keys()))


def log_file_action(action, user_id, filename, file_size, **extra):
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'user_id': user_id,
        'filename': filename,
        'file_size': file_size
    }
    log_entry.update(extra)
    save_to_csv('files_log.csv', log_entry, list(log_entry.keys()))


def log_document_action(action, user_id, doc_id, title, **extra):
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'user_id': user_id,
        'document_id': doc_id,
        'title': title
    }
    log_entry.update(extra)
    save_to_csv('documents_log.csv', log_entry, list(log_entry.keys()))


@app.route('/')
def index():
    user = get_current_user()
    files_count = File.query.count()
    users_count = User.query.count()
    documents_count = Document.query.count()
    recent_files = File.query.filter_by(is_public=True).order_by(File.uploaded_at.desc()).limit(5).all()
    return render_template('index.html', user=user, files_count=files_count,
                         users_count=users_count, documents_count=documents_count,
                         recent_files=recent_files)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_current_user():
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or len(username) < 3:
            flash('Имя пользователя должно содержать минимум 3 символа', 'danger')
            return render_template('register.html')

        if not email or '@' not in email:
            flash('Некорректный формат email', 'danger')
            return render_template('register.html')

        if not password or len(password) < 6:
            flash('Пароль должен содержать минимум 6 символов', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Пароли не совпадают', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует', 'danger')
            return render_template('register.html')

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            log_user_action('register', username, email)
            flash('Регистрация успешна! Теперь вы можете войти', 'success')
            return redirect(url_for('login'))
        except Exception:
            db.session.rollback()
            flash('Произошла ошибка при регистрации', 'danger')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_current_user():
        return redirect(url_for('index'))

    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if user and user.check_password(password):
            if not user.is_active:
                flash('Аккаунт деактивирован', 'danger')
                return render_template('login.html')

            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True

            log_user_action('login', user.username, user.email)

            flash(f'Добро пожаловать, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
            return render_template('login.html')

    return render_template('login.html')


@app.route('/logout')
def logout():
    user = get_current_user()
    if user:
        log_user_action('logout', user.username, user.email)
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    user = get_current_user()
    user_files = user.files.order_by(File.uploaded_at.desc()).all()
    user_documents = user.documents.order_by(Document.updated_at.desc()).all()
    total_size = sum(f.file_size for f in user_files)
    return render_template('profile.html', user=user, files=user_files,
                         documents=user_documents, total_size=total_size)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Файл не найден', 'danger')
            return redirect(request.url)

        file = request.files['file']
        description = request.form.get('description', '')
        is_public = request.form.get('is_public', False)

        if file.filename == '':
            flash('Файл не выбран', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            unique_filename = f"{secrets.token_hex(16)}.{get_file_extension(original_filename)}"

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)

            file_size = os.path.getsize(filepath)

            new_file = File(
                filename=unique_filename,
                original_filename=original_filename,
                file_size=file_size,
                file_type=get_file_extension(original_filename),
                user_id=session['user_id'],
                description=description,
                is_public=is_public
            )

            try:
                db.session.add(new_file)
                db.session.commit()
                log_file_action('upload', session['user_id'], original_filename, file_size)
                flash(f'Файл {original_filename} успешно загружен', 'success')
                return redirect(url_for('profile'))
            except Exception:
                db.session.rollback()
                if os.path.exists(filepath):
                    os.remove(filepath)
                flash('Ошибка при сохранении файла', 'danger')
                return redirect(request.url)
        else:
            flash('Недопустимый тип файла', 'danger')
            return redirect(request.url)

    return render_template('upload.html')


@app.route('/files')
@login_required
def list_files():
    user = get_current_user()
    user_files = user.files.order_by(File.uploaded_at.desc()).all()
    public_files = File.query.filter_by(is_public=True).order_by(File.uploaded_at.desc()).limit(20).all()
    return render_template('files.html', user=user, user_files=user_files, public_files=public_files)


@app.route('/file/<int:file_id>')
@login_required
def view_file(file_id):
    file_obj = File.query.get_or_404(file_id)
    if file_obj.user_id != session['user_id'] and not file_obj.is_public:
        flash('У вас нет доступа к этому файлу', 'danger')
        return redirect(url_for('list_files'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_obj.filename,
                             download_name=file_obj.original_filename)


@app.route('/file/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    file_obj = File.query.get_or_404(file_id)
    if file_obj.user_id != session['user_id']:
        flash('У вас нет прав для удаления', 'danger')
        return redirect(url_for('list_files'))

    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        db.session.delete(file_obj)
        db.session.commit()
        flash('Файл успешно удален', 'success')
    except Exception:
        db.session.rollback()
        flash('Ошибка при удалении файла', 'danger')

    return redirect(url_for('list_files'))


@app.route('/documents')
@login_required
def list_documents():
    user = get_current_user()
    documents = user.documents.order_by(Document.updated_at.desc()).all()
    return render_template('documents.html', user=user, documents=documents)


@app.route('/document/new', methods=['GET', 'POST'])
@login_required
def create_document():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        category = request.form.get('category', '').strip()
        tags = request.form.get('tags', '').strip()

        if not title or not content:
            flash('Заголовок и содержание обязательны', 'danger')
            return render_template('document_form.html')

        new_doc = Document(
            title=title,
            content=content,
            user_id=session['user_id'],
            category=category,
            tags=tags
        )

        try:
            db.session.add(new_doc)
            db.session.commit()
            log_document_action('create', session['user_id'], new_doc.id, title)
            flash('Документ успешно создан', 'success')
            return redirect(url_for('list_documents'))
        except Exception:
            db.session.rollback()
            flash('Ошибка при создании документа', 'danger')
            return render_template('document_form.html')

    return render_template('document_form.html')


@app.route('/document/<int:doc_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.user_id != session['user_id']:
        flash('У вас нет прав для редактирования', 'danger')
        return redirect(url_for('list_documents'))

    if request.method == 'POST':
        doc.title = request.form.get('title', '').strip()
        doc.content = request.form.get('content', '').strip()
        doc.category = request.form.get('category', '').strip()
        doc.tags = request.form.get('tags', '').strip()

        if not doc.title or not doc.content:
            flash('Заголовок и содержание обязательны', 'danger')
            return render_template('document_form.html', document=doc)

        try:
            db.session.commit()
            flash('Документ успешно обновлен', 'success')
            return redirect(url_for('list_documents'))
        except Exception:
            db.session.rollback()
            flash('Ошибка при обновлении документа', 'danger')
            return render_template('document_form.html', document=doc)

    return render_template('document_form.html', document=doc)


@app.route('/document/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.user_id != session['user_id']:
        flash('У вас нет прав для удаления', 'danger')
        return redirect(url_for('list_documents'))

    try:
        db.session.delete(doc)
        db.session.commit()
        flash('Документ успешно удален', 'success')
    except Exception:
        db.session.rollback()
        flash('Ошибка при удалении документа', 'danger')

    return redirect(url_for('list_documents'))


@app.route('/api/users', methods=['GET'])
def api_get_users():
    return jsonify([user.to_dict() for user in User.query.all()])


@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'Все поля обязательны'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Пароль слишком короткий'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Пользователь уже существует'}), 409

    new_user = User(username=username, email=email)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Пользователь создан', 'user': new_user.to_dict()}), 201
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Ошибка сервера'}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user = User.query.filter(
        (User.username == data.get('username_or_email')) |
        (User.email == data.get('username_or_email'))
    ).first()

    if user and user.check_password(data.get('password', '')):
        return jsonify({'message': 'Успешный вход', 'user': user.to_dict()})
    return jsonify({'error': 'Неверные учетные данные'}), 401


@app.route('/api/files', methods=['GET'])
@login_required
def api_get_files():
    user = get_current_user()
    return jsonify([f.to_dict() for f in user.files.all()])


@app.route('/api/documents', methods=['GET'])
@login_required
def api_get_documents():
    user = get_current_user()
    return jsonify([doc.to_dict() for doc in user.documents.all()])


@app.route('/api/statistics', methods=['GET'])
@login_required
def api_statistics():
    user = get_current_user()
    files_count = user.files.count()
    documents_count = user.documents.count()
    total_size = sum(f.file_size for f in user.files.all())
    return jsonify({
        'files_count': files_count,
        'documents_count': documents_count,
        'total_size_bytes': total_size,
        'total_size_mb': round(total_size / (1024 * 1024), 2)
    })


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    app.run(host=host, port=port, debug=False)

