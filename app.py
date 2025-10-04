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

# -----------------------------
# Admin Routes
# -----------------------------
@app.route("/admin/users", methods=["GET","POST"])
@login_required
@require_roles("admin")
def admin_users():
    if request.method == "POST":
        try:
            # Check if email already exists
            existing_user = User.query.filter_by(email=request.form["email"].lower().strip()).first()
            if existing_user:
                flash("Email already exists")
                return redirect(url_for("admin_users"))
            
            u = User(
                company_id=current_user.company_id,
                name=request.form["name"].strip(),
                email=request.form["email"].lower().strip(),
                role=request.form["role"],
                manager_id=int(request.form["manager_id"]) if request.form.get("manager_id") else None,
                is_manager_approver=bool(request.form.get("is_manager_approver"))
            )
            u.set_password(request.form["password"])
            db.session.add(u)
            db.session.commit()
            flash("User created successfully")
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating user: {str(e)}")
        return redirect(url_for("admin_users"))
    
    users = User.query.filter_by(company_id=current_user.company_id).order_by(User.name).all()
    return render_template("users.html", users=users)

@app.route("/admin/rules", methods=["GET","POST"])
@login_required
@require_roles("admin")
def rules():
    if request.method == "POST":
        try:
            r = ApprovalRule(
                company_id=current_user.company_id,
                name=request.form["name"].strip(),
                sequence_csv=request.form.get("sequence_csv") or None,
                min_percent_approve=int(request.form["min_percent_approve"]) if request.form.get("min_percent_approve") else None,
                specific_approver_id=int(request.form["specific_approver_id"]) if request.form.get("specific_approver_id") else None,
                hybrid_any=bool(request.form.get("hybrid_any"))
            )
            db.session.add(r)
            db.session.commit()
            flash("Rule created successfully")
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating rule: {str(e)}")
        return redirect(url_for("rules"))
    
    rules = ApprovalRule.query.filter_by(company_id=current_user.company_id, active=True).order_by(ApprovalRule.name).all()
    return render_template("rules.html", rules=rules)

# -----------------------------
# Employee Routes
# -----------------------------
@app.route("/expenses/new", methods=["GET","POST"])
@login_required
@require_roles("employee")
def new_expense():
    rules = ApprovalRule.query.filter_by(company_id=current_user.company_id, active=True).order_by(ApprovalRule.name).all()
    
    if request.method == "POST":
        try:
            category = request.form["category"]
            description = request.form.get("description")
            expense_date = datetime.fromisoformat(request.form["expense_date"]).date()
            amount = Decimal(request.form["amount"])
            currency = request.form["currency"].upper()
            rule_id = int(request.form["rule_id"]) if request.form.get("rule_id") else None

            # Currency normalization
            company_ccy = current_user.company.currency
            if currency == company_ccy:
                norm = quant2(amount)
            else:
                rate = get_rate(currency, company_ccy)
                norm = quant2(amount * rate)

            e = Expense(
                company_id=current_user.company_id,
                submitter_id=current_user.id,
                category=category, 
                description=description,
                expense_date=expense_date,
                amount=quant2(amount), 
                currency=currency,
                amount_company_ccy=norm,
                status="pending",
                rule_id=rule_id
            )
            db.session.add(e)
            db.session.flush()

            # Build approval workflow
            if rule_id:
                rule = db.session.get(ApprovalRule, rule_id)
                build_steps_for_rule(e, rule)
            else:
                # Default manager approval if exists
                if current_user.manager_id and current_user.is_manager_approver:
                    st = ApprovalStep(expense_id=e.id, approver_id=current_user.manager_id, sequence=1)
                    db.session.add(st)

            db.session.commit()
            flash("Expense submitted successfully")
            return redirect(url_for("my_expenses"))
        
        except Exception as e:
            db.session.rollback()
            flash(f"Error submitting expense: {str(e)}")
    
    return render_template("new_expense.html", rules=rules)

@app.route("/expenses/mine")
@login_required
@require_roles("employee")
def my_expenses():
    exps = (Expense.query
           .filter_by(submitter_id=current_user.id)
           .order_by(Expense.created_at.desc())
           .all())
    return render_template("my_expenses.html", expenses=exps)

# -----------------------------
# Manager/Admin Routes
# -----------------------------
@app.route("/approvals")
@login_required
@require_roles("manager","admin")
def approvals():
    # Get steps awaiting current user's approval
    steps = (ApprovalStep.query
             .join(Expense, ApprovalStep.expense_id == Expense.id)
             .filter(ApprovalStep.approver_id == current_user.id,
                     Expense.company_id == current_user.company_id,
                     ApprovalStep.decision.is_(None),
                     Expense.status == "pending")
             .order_by(Expense.created_at.desc(), ApprovalStep.sequence.asc())
             .all())
    
    rows = []
    for s in steps:
        # Only show if this is the current pending step
        first_pending = current_pending_step(s.expense)
        if first_pending and first_pending.id == s.id:
            rows.append({"e": s.expense, "step": s})
    
    company_ccy = current_user.company.currency
    return render_template("approvals.html", rows=rows, company_ccy=company_ccy)

@app.route("/approvals/decide/<int:step_id>", methods=["POST"])
@login_required
@require_roles("manager","admin")
def decide(step_id):
    try:
        step = db.session.get(ApprovalStep, step_id)
        if not step or step.approver_id != current_user.id:
            abort(404)
        
        expense = step.expense
        if expense.status != "pending":
            flash("Expense is no longer pending")
            return redirect(url_for("approvals"))
        
        # Ensure this is the current pending step
        if current_pending_step(expense).id != step.id:
            flash("Not your turn to approve")
            return redirect(url_for("approvals"))
        
        decision = request.form["decision"]
        comment = request.form.get("comment")
        
        step.decision = decision
        step.comment = comment
        step.decided_at = datetime.utcnow()
        db.session.flush()
        
        if decision == "rejected":
            expense.status = "rejected"
            db.session.commit()
            flash("Expense rejected")
            return redirect(url_for("approvals"))
        
        # Check conditional approval rules
        rule = expense.rule
        cond_result = evaluate_conditional(rule, expense) if rule else None
        next_pending = current_pending_step(expense)
        
        if next_pending and not (cond_result is True):
            db.session.commit()
            flash("Approved - forwarded to next approver")
            return redirect(url_for("approvals"))
        
        # Final approval
        if not next_pending or cond_result is True:
            expense.status = "approved"
            expense.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash("Expense fully approved")
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error processing decision: {str(e)}")
    
    return redirect(url_for("approvals"))

# -----------------------------
# Utility Routes
# -----------------------------
@app.route("/ocr/parse", methods=["POST"])
@login_required
def ocr_parse():
    # OCR stub for future implementation
    return jsonify({
        "category": "Restaurant",
        "description": "Auto-parsed from receipt OCR",
        "expense_date": datetime.utcnow().date().isoformat(),
        "amount": "23.50",
        "currency": current_user.company.currency
    })

@app.route("/debug/seed")
@login_required
@require_roles("admin")
def seed():
    """Create sample users for testing"""
    try:
        m = User(
            company_id=current_user.company_id, 
            email=f"mgr+{uuid4().hex[:6]}@example.com", 
            name="Manager One", 
            role="manager"
        )
        m.set_password("password123")
        
        e = User(
            company_id=current_user.company_id, 
            email=f"emp+{uuid4().hex[:6]}@example.com", 
            name="Employee One", 
            role="employee", 
            manager=m, 
            is_manager_approver=True
        )
        e.set_password("password123")
        
        db.session.add_all([m, e])
        db.session.commit()
        
        flash(f"Created Manager: {m.email} and Employee: {e.email} (password: password123)")
        
    except Exception as ex:
        db.session.rollback()
        flash(f"Error seeding data: {str(ex)}")
    
    return redirect(url_for("admin_users"))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
