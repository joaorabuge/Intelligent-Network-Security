# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin

db = SQLAlchemy()  # Inicialização do banco de dados
bcrypt = Bcrypt()  # Inicialização do bcrypt para senhas
login_manager = LoginManager()  # Gerenciador de login para autenticação

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class PCAPResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    result = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='pcap_results')

class RealtimeResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    result = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='realtime_results')

# New model for storing context files
class ChatContext(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    analysis_type = db.Column(db.String(50), nullable=False)  # e.g. "real_time" or "pcap"
    result_id = db.Column(db.Integer, nullable=False)         # ID of the corresponding analysis result
    file_path = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship('User', backref='chat_contexts')


class User(UserMixin, db.Model):  # Adicione UserMixin aqui
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    pcap_results = db.relationship('PCAPResult', back_populates='user', lazy=True)
    realtime_results = db.relationship('RealtimeResult', back_populates='user', lazy=True)
