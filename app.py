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
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "postgresql://exp_user:strongpass@localhost:5432/expenses")
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

# -----------------------------
# Utilities
# -----------------------------
COUNTRY_CACHE = {}
RATES_CACHE = {}

def require_roles(*roles):
    def deco(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_mgr.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return inner
    return deco

@login_mgr.user_loader
def load_user(uid): 
    return db.session.get(User, int(uid))

def get_country_currency(country_name):
    if COUNTRY_CACHE.get(country_name): 
        return COUNTRY_CACHE[country_name]
    try:
        resp = requests.get("https://restcountries.com/v3.1/all?fields=name,currencies", timeout=15)
        resp.raise_for_status()
        for c in resp.json():
            name = c.get("name", {}).get("common") or c.get("name", {}).get("official")
            currs = list((c.get("currencies") or {}).keys())
            if not name or not currs: 
                continue
            COUNTRY_CACHE[name] = currs[0]
        if country_name in COUNTRY_CACHE:
            return COUNTRY_CACHE[country_name]
        for k in COUNTRY_CACHE:
            if k.lower() == country_name.lower():
                return COUNTRY_CACHE[k]
    except Exception as e:
        print(f"Error fetching currency for {country_name}: {e}")
    return "USD"

def get_rate(base, target):
    if base == target:
        return Decimal("1")
    
    key = (base, target)
    if key in RATES_CACHE and (datetime.utcnow() - RATES_CACHE[key]["ts"]).seconds < 3600:
        return RATES_CACHE[key]["rate"]
    try:
        resp = requests.get(f"https://api.exchangerate-api.com/v4/latest/{base}", timeout=15)
        resp.raise_for_status()
        data = resp.json()
        rate = data["rates"].get(target)
        if rate:
            RATES_CACHE[key] = {"rate": Decimal(str(rate)), "ts": datetime.utcnow()}
            return RATES_CACHE[key]["rate"]
    except Exception as e:
        print(f"Error fetching exchange rate {base} to {target}: {e}")
    return Decimal("1")

def quant2(x):
    return Decimal(x).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

def build_steps_for_rule(expense, rule: ApprovalRule):
    # Clear existing steps
    ApprovalStep.query.filter_by(expense_id=expense.id).delete()
    
    seq_ids = []
    # Optional manager first if submitter has manager approver enabled
    if expense.submitter.manager_id and expense.submitter.is_manager_approver:
        seq_ids.append(expense.submitter.manager_id)
    
    # Admin-defined sequence
    if rule.sequence_csv:
        seq_ids.extend([int(i) for i in rule.sequence_csv.split(",") if i.strip().isdigit()])
    
    # Create approval steps
    for idx, uid in enumerate(seq_ids, start=1):
        st = ApprovalStep(expense=expense, approver_id=uid, sequence=idx)
        db.session.add(st)

def evaluate_conditional(rule: ApprovalRule, expense: Expense):
    steps = [s for s in expense.steps if s.decision in ("approved","rejected")]
    if not steps: 
        return None
    
    approvals = sum(1 for s in steps if s.decision == "approved")
    total = len([s for s in expense.steps if s.decision is not None])
    percent_ok = None
    specific_ok = None

    if rule.min_percent_approve:
        percent = 0 if total == 0 else int((approvals/total)*100)
        percent_ok = percent >= rule.min_percent_approve
    
    if rule.specific_approver_id:
        specific_ok = any((s.approver_id == rule.specific_approver_id and s.decision=="approved") for s in steps)

    checks = []
    if rule.min_percent_approve is not None: 
        checks.append(percent_ok)
    if rule.specific_approver_id is not None: 
        checks.append(specific_ok)
    
    if not checks: 
        return None
    
    if rule.hybrid_any:
        return any(checks)
    else:
        return all(checks)

def current_pending_step(expense: Expense):
    for s in sorted(expense.steps, key=lambda x: x.sequence):
        if s.decision is None:
            return s
    return None

# -----------------------------
# Database Initialization
# -----------------------------
def init_db():
    """Initialize database with tables"""
    try:
        db.create_all()
        print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {e}")
        raise

# Initialize database on startup
with app.app_context():
    init_db()

# -----------------------------
# Routes: Auth
# -----------------------------
@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        try:
            name = request.form["name"].strip()
            email = request.form["email"].lower().strip()
            pw = request.form["password"]
            company_name = request.form["company"].strip()
            country = request.form["country"].strip()
            
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash("Email already registered")
                return render_template("signup.html")
            
            currency = get_country_currency(country)
            comp = Company(name=company_name, country=country, currency=currency)
            db.session.add(comp)
            db.session.flush()
            
            user = User(company_id=comp.id, email=email, name=name, role="admin", is_manager_approver=True)
            user.set_password(pw)
            db.session.add(user)
            db.session.commit()
            
            login_user(user)
            flash(f"Company created with currency {currency}")
            return redirect(url_for("dashboard"))
        
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating account: {str(e)}")
            return render_template("signup.html")
    
    return render_template("signup.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].lower().strip()
        pw = request.form["password"]
        user = User.query.filter_by(email=email, is_active_user=True).first()
        if user and user.check_password(pw):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")

