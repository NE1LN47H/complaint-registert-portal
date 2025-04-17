from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///complaints.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size
db = SQLAlchemy(app)

# Create upload folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(10), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    admin_role = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')
    assigned_to = db.Column(db.String(20), default='village_officer')
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    creator = db.relationship('User', backref='complaints')
    images = db.relationship('ComplaintImage', backref='complaint', lazy=True, cascade="all, delete-orphan")

class ComplaintImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    image_path = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    complaint = db.relationship('Complaint', backref='messages')
    sender = db.relationship('User', backref='messages')

# Helper Functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def validate_phone(phone):
    return len(phone) == 10 and phone.isdigit()

def validate_password(password):
    pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return re.match(pattern, password)

def get_admin_count(role):
    return User.query.filter_by(is_admin=True, admin_role=role).count()

def is_admin_limit_reached(role):
    max_admins = 1
    return get_admin_count(role) >= max_admins

# Context Processor to make 'now' available in all templates
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            if user.is_admin:
                session['admin_role'] = user.admin_role
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not validate_email(email):
            flash('Invalid email format', 'danger')
        elif not validate_phone(phone):
            flash('Phone number must be 10 digits', 'danger')
        elif not validate_password(password):
            flash('Password must be at least 8 characters with uppercase, lowercase, number, and special character', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
        elif User.query.filter_by(phone=phone).first():
            flash('Phone number already registered', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(
                name=name,
                email=email,
                phone=phone,
                password=hashed_password,
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('user_signup.html')

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        admin_role = request.form['admin_role']
        
        if not validate_email(email):
            flash('Invalid email format', 'danger')
        elif not validate_phone(phone):
            flash('Phone number must be 10 digits', 'danger')
        elif not validate_password(password):
            flash('Password must be at least 8 characters with uppercase, lowercase, number, and special character', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
        elif User.query.filter_by(phone=phone).first():
            flash('Phone number already registered', 'danger')
        elif is_admin_limit_reached(admin_role):
            flash(f'Only one {admin_role.replace("_", " ")} can be registered', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            new_admin = User(
                name=name,
                email=email,
                phone=phone,
                password=hashed_password,
                is_admin=True,
                admin_role=admin_role
            )
            db.session.add(new_admin)
            db.session.commit()
            flash('Admin registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('admin_signup.html')

@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    complaints = Complaint.query.filter_by(created_by=user.id).order_by(Complaint.created_at.desc()).all()
    return render_template('user_dashboard.html', complaints=complaints, current_user=user)

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    admin_role = session['admin_role']
    complaints = Complaint.query.filter_by(assigned_to=admin_role).order_by(Complaint.created_at.desc()).all()
    return render_template('admin_dashboard.html', complaints=complaints, admin_role=admin_role, current_user=user)

@app.route('/complaint/create', methods=['GET', 'POST'])
def create_complaint():
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    categories = [
        'Roads',
        'Water Supply',
        'Electricity',
        'Sanitation',
        'Infrastructure',
        'Public Safety',
        'Health Services',
        'Education',
        'Agriculture',
        'Others'
    ]
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        files = request.files.getlist('images')
        
        if not title or not description or not category:
            flash('All fields are required', 'danger')
        else:
            new_complaint = Complaint(
                title=title,
                description=description,
                category=category,
                created_by=user.id,
                assigned_to='village_officer'
            )
            db.session.add(new_complaint)
            db.session.commit()
            
            # Handle image uploads
            for file in files:
                if file and allowed_file(file.filename):
                    try:
                        filename = secure_filename(f"{datetime.now().timestamp()}_{file.filename}")
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        
                        new_image = ComplaintImage(
                            complaint_id=new_complaint.id,
                            image_path=filename
                        )
                        db.session.add(new_image)
                    except Exception as e:
                        flash(f'Error uploading file {file.filename}: {str(e)}', 'warning')
                        continue
            
            db.session.commit()
            flash('Complaint submitted successfully!', 'success')
            return redirect(url_for('user_dashboard'))
    
    return render_template('create_complaint.html', current_user=user, categories=categories)

@app.route('/complaint/<int:complaint_id>')
def view_complaint(complaint_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    complaint = Complaint.query.get_or_404(complaint_id)
    
    if not session.get('is_admin') and complaint.created_by != user.id:
        flash('You are not authorized to view this complaint', 'danger')
        return redirect(url_for('user_dashboard'))
    
    if session.get('is_admin') and complaint.assigned_to != session.get('admin_role'):
        flash('This complaint is not assigned to you', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    messages = Message.query.filter_by(complaint_id=complaint_id).order_by(Message.created_at.asc()).all()
    images = ComplaintImage.query.filter_by(complaint_id=complaint_id).all()
    return render_template('view_complaint.html', complaint=complaint, messages=messages, images=images, current_user=user)

@app.route('/complaint/<int:complaint_id>/update', methods=['POST'])
def update_complaint(complaint_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    complaint = Complaint.query.get_or_404(complaint_id)
    
    if complaint.assigned_to != session.get('admin_role'):
        flash('This complaint is not assigned to you', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    action = request.form.get('action')
    
    if action == 'resolve':
        complaint.status = 'resolved'
        db.session.commit()
        flash('Complaint marked as resolved', 'success')
    elif action == 'progress':
        complaint.status = 'in_progress'
        db.session.commit()
        flash('Complaint status updated to in progress', 'success')
    elif action == 'escalate':
        if complaint.assigned_to == 'village_officer':
            complaint.assigned_to = 'sub_collector'
        elif complaint.assigned_to == 'sub_collector':
            complaint.assigned_to = 'collector'
        complaint.status = 'pending'
        db.session.commit()
        flash('Complaint escalated to higher authority', 'success')
    
    return redirect(url_for('view_complaint', complaint_id=complaint_id))

@app.route('/complaint/<int:complaint_id>/message', methods=['POST'])
def send_message(complaint_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    try:
        user = User.query.get(session['user_id'])
        complaint = Complaint.query.get_or_404(complaint_id)
        message_text = request.form.get('message', '').strip()

        # Validate access
        if not session.get('is_admin') and complaint.created_by != user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        if session.get('is_admin') and complaint.assigned_to != session.get('admin_role'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        # Validate message - allow empty messages but with minimum length check
        if len(message_text) > 1000:
            return jsonify({'success': False, 'error': 'Message too long (max 1000 chars)'}), 400

        # Create and save message (even if empty)
        new_message = Message(
            complaint_id=complaint_id,
            sender_id=user.id,
            message=message_text
        )
        db.session.add(new_message)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': {
                'id': new_message.id,
                'sender': user.name,
                'sender_id': user.id,
                'is_admin': user.is_admin,
                'admin_role': user.admin_role if user.is_admin else None,
                'message': message_text,
                'created_at': new_message.created_at.strftime('%d-%m-%Y %H:%M')
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Server error: ' + str(e)}), 500

@app.route('/api/messages/<int:complaint_id>')
def get_messages(complaint_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        user = User.query.get(session['user_id'])
        complaint = Complaint.query.get_or_404(complaint_id)
        
        # Check access
        if not session.get('is_admin') and complaint.created_by != user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        if session.get('is_admin') and complaint.assigned_to != session.get('admin_role'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        messages = Message.query.filter_by(complaint_id=complaint_id)\
                      .order_by(Message.created_at.asc())\
                      .all()
        
        messages_data = [{
            'id': msg.id,
            'sender': msg.sender.name,
            'sender_id': msg.sender.id,
            'is_admin': msg.sender.is_admin,
            'admin_role': msg.sender.admin_role if msg.sender.is_admin else None,
            'message': msg.message,
            'created_at': msg.created_at.strftime('%d-%m-%Y %H:%M')
        } for msg in messages]
        
        return jsonify({'success': True, 'messages': messages_data})
    
    except Exception as e:
        return jsonify({'success': False, 'error': 'Server error: ' + str(e)}), 500

@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return {'current_user': user}
    return {'current_user': None}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)