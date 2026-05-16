import os
import secrets
import csv
import json
import re
import mimetypes
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

if os.environ.get('RENDER'):
    db_path = '/opt/render/project/src/instance/site.db'
elif os.environ.get('HEROKU'):
    db_path = os.environ.get('DATABASE_URL', 'sqlite:///instance/site.db')
else:
    basedir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(basedir, 'instance', 'site.db')

db_dir = os.path.dirname(db_path)
if db_dir and not os.path.exists(db_dir):
    os.makedirs(db_dir, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}' if not db_path.startswith('postgresql') else db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True, 'pool_recycle': 300}

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', os.path.join(basedir, 'uploads'))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['DATA_FOLDER'] = os.environ.get('DATA_FOLDER', os.path.join(basedir, 'data'))
app.config['ALLOWED_IMAGE_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['ALLOWED_DOCUMENT_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'txt', 'rtf'}
app.config['ALLOWED_DATA_EXTENSIONS'] = {'csv', 'xlsx', 'xls', 'json'}

ALLOWED_EXTENSIONS = set.union(
    app.config['ALLOWED_IMAGE_EXTENSIONS'],
    app.config['ALLOWED_DOCUMENT_EXTENSIONS'],
    app.config['ALLOWED_DATA_EXTENSIONS']
)

db = SQLAlchemy(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DATA_FOLDER'], exist_ok=True)
if db_dir:
    os.makedirs(db_dir, exist_ok=True)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    files = db.relationship('File', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    documents = db.relationship('Document', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        self.last_login = datetime.utcnow()
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'is_verified': self.is_verified
        }
    
    def get_file_count(self):
        return self.files.count()
    
    def get_document_count(self):
        return self.documents.count()
    
    def get_total_storage_used(self):
        total = db.session.query(db.func.sum(File.file_size)).filter_by(user_id=self.id).scalar()
        return total or 0

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    original_filename = db.Column(db.String(256), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    mime_type = db.Column(db.String(100))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    description = db.Column(db.Text)
    is_public = db.Column(db.Boolean, default=False)
    download_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_size': self.file_size,
            'file_size_human': self.format_size(self.file_size),
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'user_id': self.user_id,
            'username': self.owner.username if self.owner else None,
            'description': self.description,
            'is_public': self.is_public,
            'download_count': self.download_count
        }
    
    @staticmethod
    def format_size(size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def increment_download_count(self):
        self.download_count = (self.download_count or 0) + 1

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    category = db.Column(db.String(100), index=True)
    tags = db.Column(db.String(300))
    is_published = db.Column(db.Boolean, default=True)
    view_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'content_preview': self.content[:200] + '...' if len(self.content) > 200 else self.content,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'user_id': self.user_id,
            'username': self.owner.username if self.owner else None,
            'category': self.category,
            'tags': self.tags,
            'tags_list': self.get_tags_list(),
            'is_published': self.is_published,
            'view_count': self.view_count
        }
    
    def get_tags_list(self):
        if not self.tags:
            return []
        return [tag.strip() for tag in self.tags.split(',') if tag.strip()]
    
    def increment_view_count(self):
        self.view_count = (self.view_count or 0) + 1

def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def is_image_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in app.config['ALLOWED_IMAGE_EXTENSIONS']

def is_document_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in app.config['ALLOWED_DOCUMENT_EXTENSIONS']

def get_file_extension(filename):
    if not filename or '.' not in filename:
        return ''
    return filename.rsplit('.', 1)[1].lower()

def get_mime_type(filename):
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type or 'application/octet-stream'

def generate_unique_filename(original_filename):
    ext = get_file_extension(original_filename)
    unique_name = f"{secrets.token_hex(16)}.{ext}"
    return unique_name

def validate_username(username):
    if not username or len(username) < 3 or len(username) > 80:
        return False
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False
    return True

def validate_email(email):
    if not email or len(email) > 120:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if not password or len(password) < 6:
        return False
    return True

def sanitize_filename(filename):
    return secure_filename(filename)

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

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            abort(403)
        user = User.query.get(session['user_id'])
        if not user or not user.is_active:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    if 'user_id' not in session:
        return None
    return User.query.get(session['user_id'])

def save_to_csv(filename, data, fieldnames):
    filepath = os.path.join(app.config['DATA_FOLDER'], filename)
    file_exists = os.path.exists(filepath)
    with open(filepath, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

def load_from_csv(filename):
    filepath = os.path.join(app.config['DATA_FOLDER'], filename)
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)

def save_to_json(filename, data):
    filepath = os.path.join(app.config['DATA_FOLDER'], filename)
    with open(filepath, 'w', encoding='utf-8') as jsonfile:
        json.dump(data, jsonfile, indent=4, ensure_ascii=False)

def load_from_json(filename):
    filepath = os.path.join(app.config['DATA_FOLDER'], filename)
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as jsonfile:
        return json.load(jsonfile)

def log_user_action(action, username, email, **extra):
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'username': username,
        'email': email,
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', '')[:200]
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

@app.context_processor
def inject_globals():
    return {
        'current_user': get_current_user,
        'year': datetime.now().year,
        'app_name': 'FileHub'
    }

@app.route('/')
def index():
    user = get_current_user()
    files_count = File.query.count()
    users_count = User.query.count()
    documents_count = Document.query.count()
    recent_files = File.query.filter_by(is_public=True).order_by(File.uploaded_at.desc()).limit(5).all()
    recent_documents = Document.query.filter_by(is_published=True).order_by(Document.updated_at.desc()).limit(5).all()
    return render_template('index.html', user=user, files_count=files_count, 
                         users_count=users_count, documents_count=documents_count,
                         recent_files=recent_files, recent_documents=recent_documents)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_current_user():
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not validate_username(username):
            flash('Имя пользователя должно содержать 3-80 символов (буквы, цифры, _, -)', 'danger')
            return render_template('register.html')
        
        if not validate_email(email):
            flash('Некорректный формат email', 'danger')
            return render_template('register.html')
        
        if not validate_password(password):
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
        except Exception as e:
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
        remember = request.form.get('remember', False)
        
        if not username_or_email or not password:
            flash('Введите имя пользователя/почту и пароль', 'danger')
            return render_template('login.html')
        
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
            
            user.update_last_login()
            db.session.commit()
            
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
    
    total_size = user.get_total_storage_used()
    file_count = user.get_file_count()
    document_count = user.get_document_count()
    
    return render_template('profile.html', user=user, files=user_files, 
                         documents=user_documents, total_size=total_size,
                         file_count=file_count, document_count=document_count)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Файл не найден в запросе', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        description = request.form.get('description', '').strip()
        is_public = request.form.get('is_public', False)
        
        if not file or file.filename == '':
            flash('Файл не выбран', 'danger')
            return redirect(request.url)
        
        if not allowed_file(file.filename):
            flash('Недопустимый тип файла', 'danger')
            return redirect(request.url)
        
        original_filename = sanitize_filename(file.filename)
        unique_filename = generate_unique_filename(original_filename)
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        file_size = os.path.getsize(filepath)
        file_type = get_file_extension(original_filename)
        mime_type = get_mime_type(original_filename)
        
        if file_size > app.config['MAX_CONTENT_LENGTH']:
            if os.path.exists(filepath):
                os.remove(filepath)
            flash('Файл превышает максимальный размер (16MB)', 'danger')
            return redirect(request.url)
        
        new_file = File(
            filename=unique_filename,
            original_filename=original_filename,
            file_size=file_size,
            file_type=file_type,
            mime_type=mime_type,
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
        except Exception as e:
            db.session.rollback()
            if os.path.exists(filepath):
                os.remove(filepath)
            flash('Ошибка при сохранении файла в базу данных', 'danger')
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
    
    file_obj.increment_download_count()
    db.session.commit()
    
    log_file_action('download', file_obj.user_id, file_obj.original_filename, file_obj.file_size, file_id=file_id)
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_obj.filename, 
                             download_name=file_obj.original_filename, as_attachment=True)

@app.route('/file/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    file_obj = File.query.get_or_404(file_id)
    
    if file_obj.user_id != session['user_id']:
        flash('У вас нет прав для удаления этого файла', 'danger')
        return redirect(url_for('list_files'))
    
    original_filename = file_obj.original_filename
    file_size = file_obj.file_size
    
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        
        db.session.delete(file_obj)
        db.session.commit()
        
        log_file_action('delete', session['user_id'], original_filename, file_size, file_id=file_id)
        
        flash('Файл успешно удален', 'success')
    except Exception as e:
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
        
        if not title or len(title) > 200:
            flash('Заголовок обязателен (макс. 200 символов)', 'danger')
            return render_template('document_form.html')
        
        if not content:
            flash('Содержание документа обязательно', 'danger')
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
        except Exception as e:
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
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        category = request.form.get('category', '').strip()
        tags = request.form.get('tags', '').strip()
        
        if not title or len(title) > 200:
            flash('Заголовок обязателен (макс. 200 символов)', 'danger')
            return render_template('document_form.html', document=doc)
        
        if not content:
            flash('Содержание документа обязательно', 'danger')
            return render_template('document_form.html', document=doc)
        
        doc.title = title
        doc.content = content
        doc.category = category
        doc.tags = tags
        
        try:
            db.session.commit()
            log_document_action('update', session['user_id'], doc_id, title)
            flash('Документ успешно обновлен', 'success')
            return redirect(url_for('list_documents'))
        except Exception as e:
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
    
    title = doc.title
    doc_id_log = doc.id
    
    try:
        db.session.delete(doc)
        db.session.commit()
        log_document_action('delete', session['user_id'], doc_id_log, title)
        flash('Документ успешно удален', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при удалении документа', 'danger')
    
    return redirect(url_for('list_documents'))

@app.route('/api/users', methods=['GET'])
def api_get_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@app.route('/api/users/<int:user_id>', methods=['GET'])
def api_get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

@app.route('/api/register', methods=['POST'])
def api_register():
    if not request.is_json:
        return jsonify({'error': 'Content-Type должен быть application/json'}), 400
    
    data = request.get_json()
    
    username = data.get('username', '').strip() if data.get('username') else ''
    email = data.get('email', '').strip() if data.get('email') else ''
    password = data.get('password', '')
    
    if not validate_username(username):
        return jsonify({'error': 'Некорректное имя пользователя'}), 400
    
    if not validate_email(email):
        return jsonify({'error': 'Некорректный email'}), 400
    
    if not validate_password(password):
        return jsonify({'error': 'Пароль слишком короткий'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Пользователь уже существует'}), 409
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email уже зарегистрирован'}), 409
    
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        log_user_action('api_register', username, email)
        return jsonify({'message': 'Пользователь создан', 'user': new_user.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Ошибка сервера'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    if not request.is_json:
        return jsonify({'error': 'Content-Type должен быть application/json'}), 400
    
    data = request.get_json()
    username_or_email = data.get('username_or_email', '')
    password = data.get('password', '')
    
    user = User.query.filter(
        (User.username == username_or_email) | (User.email == username_or_email)
    ).first()
    
    if user and user.check_password(password) and user.is_active:
        user.update_last_login()
        db.session.commit()
        log_user_action('api_login', user.username, user.email)
        return jsonify({'message': 'Успешный вход', 'user': user.to_dict()})
    
    return jsonify({'error': 'Неверные учетные данные'}), 401

@app.route('/api/files', methods=['GET'])
@login_required
def api_get_files():
    user = get_current_user()
    files = user.files.order_by(File.uploaded_at.desc()).all()
    return jsonify([f.to_dict() for f in files])

@app.route('/api/files', methods=['POST'])
@login_required
def api_upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Файл не найден'}), 400
    
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'error': 'Файл не выбран'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Недопустимый тип файла'}), 400
    
    original_filename = sanitize_filename(file.filename)
    unique_filename = generate_unique_filename(original_filename)
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(filepath)
    
    file_size = os.path.getsize(filepath)
    
    if file_size > app.config['MAX_CONTENT_LENGTH']:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': 'Файл слишком большой'}), 400
    
    new_file = File(
        filename=unique_filename,
        original_filename=original_filename,
        file_size=file_size,
        file_type=get_file_extension(original_filename),
        mime_type=get_mime_type(original_filename),
        user_id=session['user_id'],
        description=request.form.get('description', ''),
        is_public=request.form.get('is_public', 'false').lower() == 'true'
    )
    
    try:
        db.session.add(new_file)
        db.session.commit()
        log_file_action('api_upload', session['user_id'], original_filename, file_size)
        return jsonify({'message': 'Файл загружен', 'file': new_file.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': 'Ошибка сервера'}), 500

@app.route('/api/documents', methods=['GET'])
@login_required
def api_get_documents():
    user = get_current_user()
    documents = user.documents.order_by(Document.updated_at.desc()).all()
    return jsonify([doc.to_dict() for doc in documents])

@app.route('/api/documents', methods=['POST'])
@login_required
def api_create_document():
    if not request.is_json:
        return jsonify({'error': 'Content-Type должен быть application/json'}), 400
    
    data = request.get_json()
    
    title = data.get('title', '').strip() if data.get('title') else ''
    content = data.get('content', '').strip() if data.get('content') else ''
    
    if not title or len(title) > 200:
        return jsonify({'error': 'Заголовок обязателен (макс. 200 символов)'}), 400
    
    if not content:
        return jsonify({'error': 'Содержание обязательно'}), 400
    
    new_doc = Document(
        title=title,
        content=content,
        user_id=session['user_id'],
        category=data.get('category', ''),
        tags=data.get('tags', '')
    )
    
    try:
        db.session.add(new_doc)
        db.session.commit()
        log_document_action('api_create', session['user_id'], new_doc.id, title)
        return jsonify({'message': 'Документ создан', 'document': new_doc.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Ошибка сервера'}), 500

@app.route('/api/statistics', methods=['GET'])
@login_required
def api_statistics():
    user = get_current_user()
    
    files_count = user.files.count()
    documents_count = user.documents.count()
    total_size = user.get_total_storage_used()
    
    public_files_count = user.files.filter_by(is_public=True).count()
    published_docs_count = user.documents.filter_by(is_published=True).count()
    
    return jsonify({
        'files_count': files_count,
        'documents_count': documents_count,
        'public_files_count': public_files_count,
        'published_docs_count': published_docs_count,
        'total_size_bytes': total_size,
        'total_size_human': File.format_size(total_size),
        'total_size_mb': round(total_size / (1024 * 1024), 2),
        'user_since': user.created_at.isoformat() if user.created_at else None
    })

@app.route('/api/search/files', methods=['GET'])
@login_required
def api_search_files():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    
    user = get_current_user()
    files = user.files.filter(
        (File.original_filename.ilike(f'%{query}%')) |
        (File.description.ilike(f'%{query}%'))
    ).order_by(File.uploaded_at.desc()).limit(20).all()
    
    return jsonify([f.to_dict() for f in files])

@app.route('/api/search/documents', methods=['GET'])
@login_required
def api_search_documents():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    
    user = get_current_user()
    documents = user.documents.filter(
        (Document.title.ilike(f'%{query}%')) |
        (Document.content.ilike(f'%{query}%')) |
        (Document.tags.ilike(f'%{query}%'))
    ).order_by(Document.updated_at.desc()).limit(20).all()
    
    return jsonify([doc.to_dict() for doc in documents])

@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Ресурс не найден'}), 404
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Доступ запрещён'}), 403
    flash('Доступ запрещён', 'danger')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Внутренняя ошибка сервера'}), 500
    return render_template('500.html'), 500

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host=host, port=port, debug=debug_mode)

