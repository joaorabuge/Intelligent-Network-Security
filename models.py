# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin
from sqlalchemy.orm import backref
from datetime import datetime  # Import para trabalhar com datas

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

# Novo modelo para armazenar contextos
class ChatContext(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    analysis_type = db.Column(db.String(50), nullable=False)  # ex.: "real_time" ou "pcap"
    result_id = db.Column(db.Integer, nullable=False)         # ID do resultado correspondente
    file_path = db.Column(db.String(255), nullable=False)
    analysis_name = db.Column(db.String(255), nullable=True)    # <-- New field for a custom name
    timestamp = db.Column(db.DateTime, default=db.func.now())
    user = db.relationship('User', backref='chat_contexts')


# Novo modelo para armazenar mensagens do chat
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    context_id = db.Column(db.Integer, db.ForeignKey('chat_context.id'), nullable=False)
    sender = db.Column(db.String(10), nullable=False)  # 'user' or 'bot'
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Update the relationship to ChatContext with cascade:
    context = db.relationship(
        'ChatContext',
        backref=backref('messages', cascade="all, delete-orphan"),
        lazy=True
    )

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    # Novo campo para armazenar o timestamp da última atualização do modelo para este usuário
    last_model_update_time = db.Column(db.DateTime, nullable=True)
    
    pcap_results = db.relationship('PCAPResult', back_populates='user', lazy=True)
    realtime_results = db.relationship('RealtimeResult', back_populates='user', lazy=True)

    def update_model_timestamp(self):
        """Atualiza o timestamp de atualização do modelo para o usuário."""
        self.last_model_update_time = datetime.utcnow()
        db.session.commit()
