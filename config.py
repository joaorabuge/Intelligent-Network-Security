import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "password"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///TESE_test.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
