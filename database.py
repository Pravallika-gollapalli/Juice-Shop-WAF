from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

b = SQLAlchemy()

db = b

class AttackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(100), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    payload = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    def __repr__(self):
        return f"<AttackLog id={self.id} type={self.attack_type} ip={self.ip}>"
