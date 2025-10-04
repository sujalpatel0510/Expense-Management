import os
from datetime import datetime
from uuid import uuid4
from functools import wraps
from decimal import Decimal, ROUND_HALF_UP

import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from passlib.hash import bcrypt

# -----------------------------
# Config
# -----------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "dev_secret_change_in_production")
# PostgreSQL connection string
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "postgresql://posygres:8511@localhost:5432/expenses")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'echo': False  # Set to True for SQL debugging
}

db = SQLAlchemy(app)
login_mgr = LoginManager(app)
login_mgr.login_view = "login"

# -----------------------------
# PostgreSQL-optimized Models
# -----------------------------
class Company(db.Model):
    __tablename__ = 'companies'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False, index=True)
    country = db.Column(db.String(80), nullable=False)
    currency = db.Column(db.String(8), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<Company {self.name}>'

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False, default="employee", index=True)  # admin, manager, employee
    is_active_user = db.Column(db.Boolean, default=True, nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    is_manager_approver = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    company = db.relationship("Company", backref=db.backref("users", cascade="all, delete-orphan"), foreign_keys=[company_id])
    manager = db.relationship("User", remote_side=[id], backref="team")

    def set_password(self, pw): 
        self.password_hash = bcrypt.hash(pw)
    
    def check_password(self, pw): 
        return bcrypt.verify(pw, self.password_hash)

    def __repr__(self):
        return f'<User {self.email}>'

class ApprovalRule(db.Model):
    __tablename__ = 'approval_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    sequence_csv = db.Column(db.Text, nullable=True)  # e.g., "12,7,33"
    min_percent_approve = db.Column(db.Integer, nullable=True)   # e.g., 60
    specific_approver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    hybrid_any = db.Column(db.Boolean, default=False, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    company = db.relationship("Company", backref=db.backref("approval_rules", cascade="all, delete-orphan"))
    specific_approver = db.relationship("User")

    def __repr__(self):
        return f'<ApprovalRule {self.name}>'

class Expense(db.Model):
    __tablename__ = 'expenses'
    
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True)
    submitter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    category = db.Column(db.String(80), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    expense_date = db.Column(db.Date, nullable=False, index=True)
    amount = db.Column(db.Numeric(12,2), nullable=False)
    currency = db.Column(db.String(8), nullable=False)
    amount_company_ccy = db.Column(db.Numeric(12,2), nullable=False)
    status = db.Column(db.String(24), default="draft", nullable=False, index=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("approval_rules.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    submitter = db.relationship("User", backref=db.backref("expenses", cascade="all, delete-orphan"))
    rule = db.relationship("ApprovalRule")
    company = db.relationship("Company")

    def __repr__(self):
        return f'<Expense {self.id}: {self.category}>'

class ApprovalStep(db.Model):
    __tablename__ = 'approval_steps'
    
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey("expenses.id", ondelete="CASCADE"), nullable=False, index=True)
    approver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    sequence = db.Column(db.Integer, nullable=False, index=True)
    decision = db.Column(db.String(16), nullable=True, index=True)  # approved/rejected/None
    comment = db.Column(db.Text, nullable=True)
    decided_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    expense = db.relationship("Expense", backref=db.backref("steps", cascade="all, delete-orphan"))
    approver = db.relationship("User")

    __table_args__ = (
        db.Index('ix_approval_steps_expense_sequence', 'expense_id', 'sequence'),
    )

    def __repr__(self):
        return f'<ApprovalStep {self.id}: Expense {self.expense_id}, Step {self.sequence}>'
