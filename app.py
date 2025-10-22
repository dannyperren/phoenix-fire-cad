
import os, uuid, json, datetime, smtplib, ssl
from email.message import EmailMessage
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, scoped_session

SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-prod")
DATABASE_URL = os.environ.get("DATABASE_URL")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/data/uploads")
BASE_URL = os.environ.get("BASE_URL")

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
FROM_EMAIL = os.environ.get("FROM_EMAIL", SMTP_USER or "no-reply@example.com")

os.makedirs(UPLOAD_DIR, exist_ok=True)

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set.")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(255))
    email_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    memberships = relationship("Membership", back_populates="user", cascade="all, delete-orphan")

class Organisation(Base):
    __tablename__ = "organisations"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    memberships = relationship("Membership", back_populates="org", cascade="all, delete-orphan")
    projects = relationship("Project", back_populates="org", cascade="all, delete-orphan")
    invites = relationship("Invite", back_populates="org", cascade="all, delete-orphan")

class Membership(Base):
    __tablename__ = "memberships"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    org_id = Column(Integer, ForeignKey("organisations.id"), nullable=False)
    role = Column(String(32), default="owner")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    user = relationship("User", back_populates="memberships")
    org = relationship("Organisation", back_populates="memberships")

class Project(Base):
    __tablename__ = "projects"
    id = Column(String(64), primary_key=True)
    org_id = Column(Integer, ForeignKey("organisations.id"), nullable=False, index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    data_json = Column(Text)
    floorplan_path = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    org = relationship("Organisation", back_populates="projects")

class EmailToken(Base):
    __tablename__ = "email_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String(64), unique=True, nullable=False, index=True)
    purpose = Column(String(32), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Invite(Base):
    __tablename__ = "invites"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organisations.id"), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    role = Column(String(32), default="viewer")
    token = Column(String(64), unique=True, nullable=False, index=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    accepted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    org = relationship("Organisation", back_populates="invites")

def init_db():
    Base.metadata.create_all(bind=engine)

def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
    init_db()
    return app

app = create_app()

def current_user(db):
    if "user_id" not in session: return None
    return db.query(User).get(session["user_id"])

def require_login(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrap

def require_org_member(roles=None):
    roles = roles or ["owner","admin","designer","viewer"]
    def deco(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            db = request.db
            if "org_id" not in session:
                flash("Select an organisation first.","warning")
                return redirect(url_for("orgs"))
            m = db.query(Membership).filter_by(user_id=session["user_id"], org_id=session["org_id"]).first()
            if not m or m.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrap
    return deco

def require_admin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        db = request.db
        m = db.query(Membership).filter_by(user_id=session["user_id"], org_id=session.get("org_id")).first()
        if not m or m.role not in ["owner","admin"]:
            abort(403)
        return f(*args, **kwargs)
    return wrap

def send_email(to, subject, html):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        print(f"[WARN] Email not configured. Would send to {to}: {subject}")
        return False
    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content("This email requires an HTML-capable client.")
    msg.add_alternative(html, subtype="html")
    ctx = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls(context=ctx)
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)
    return True

def create_email_token(db, user_id, purpose, ttl_minutes=60*24):
    token = uuid.uuid4().hex
    expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=ttl_minutes)
    db.add(EmailToken(user_id=user_id, token=token, purpose=purpose, expires_at=expires))
    db.commit()
    return token

from flask import request
@app.before_request
def _open_session():
    request.db = SessionLocal()

@app.teardown_request
def _close_session(exc):
    db = getattr(request, "db", None)
    if db is not None:
        if exc: db.rollback()
        db.close()

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        db = request.db
        email = (request.form.get("email") or "").lower().strip()
        name = (request.form.get("name") or "").strip()
        pw = request.form.get("password") or ""
        if not email or not pw:
            flash("Email and password are required.","danger")
            return redirect(url_for("register"))
        if db.query(User).filter_by(email=email).first():
            flash("Email already registered.","warning")
            return redirect(url_for("register"))
        user = User(email=email, password_hash=generate_password_hash(pw), name=name)
        db.add(user); db.commit()
        org_name = f"{name or email}'s Organisation"
        if not db.query(Organisation).filter_by(name=org_name).first():
            org = Organisation(name=org_name); db.add(org); db.commit()
            db.add(Membership(user_id=user.id, org_id=org.id, role="owner")); db.commit()
        token = create_email_token(db, user.id, "verify", ttl_minutes=60*24*3)
        if BASE_URL:
            link = f"{BASE_URL}{url_for('verify_email', token=token)}"
            send_email(user.email, "Verify your email", f"<p>Hi {name or email},</p><p>Verify your email: <a href='{link}'>Verify</a></p>")
        flash("Account created. Please check your email to verify.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/verify/<token>")
def verify_email(token):
    db = request.db
    t = db.query(EmailToken).filter_by(token=token, purpose="verify", used=False).first()
    if not t or t.expires_at < datetime.datetime.utcnow():
        flash("Verification link is invalid or expired.","danger")
        return redirect(url_for("login"))
    user = db.query(User).get(t.user_id)
    if user:
        user.email_verified = True; t.used = True; db.commit()
        flash("Email verified. You can log in now.","success")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        db = request.db
        email = (request.form.get("email") or "").lower().strip()
        pw = request.form.get("password") or ""
        user = db.query(User).filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, pw):
            session["user_id"]=user.id; session["user_email"]=user.email; session["user_name"]=user.name or user.email
            m = db.query(Membership).filter_by(user_id=user.id).first()
            if m: session["org_id"]=m.org_id
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.","danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/forgot", methods=["GET","POST"])
def forgot():
    if request.method=="POST":
        db = request.db
        email = (request.form.get("email") or "").lower().strip()
        user = db.query(User).filter_by(email=email).first()
        if user and BASE_URL:
            token = create_email_token(db, user.id, "reset", ttl_minutes=60)
            link = f"{BASE_URL}{url_for('reset_with_token', token=token)}"
            send_email(user.email, "Reset your password", f"<p>Reset your password: <a href='{link}'>Reset Link</a></p>")
        flash("If that email exists, a reset link has been sent.","info")
        return redirect(url_for("login"))
    return render_template("forgot.html")

@app.route("/reset/<token>", methods=["GET","POST"])
def reset_with_token(token):
    db = request.db
    t = db.query(EmailToken).filter_by(token=token, purpose="reset", used=False).first()
    if not t or t.expires_at < datetime.datetime.utcnow():
        flash("Reset link is invalid or expired.","danger")
        return redirect(url_for("login"))
    if request.method=="POST":
        pw = request.form.get("password") or ""
        if len(pw) < 8:
            flash("Password must be at least 8 characters.","warning")
            return redirect(request.url)
        user = db.query(User).get(t.user_id)
        user.password_hash = generate_password_hash(pw)
        t.used = True
        db.commit()
        flash("Password updated. Please log in.","success")
        return redirect(url_for("login"))
    return render_template("reset.html")

@app.route("/orgs", methods=["GET","POST"])
@require_login
def orgs():
    db = request.db
    user = current_user(db)
    if request.method=="POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Organisation name required.","warning")
            return redirect(url_for("orgs"))
        if db.query(Organisation).filter_by(name=name).first():
            flash("Organisation name already exists.","warning")
            return redirect(url_for("orgs"))
        org = Organisation(name=name); db.add(org); db.commit()
        db.add(Membership(user_id=user.id, org_id=org.id, role="owner")); db.commit()
        session["org_id"]=org.id
        flash("Organisation created.","success")
        return redirect(url_for("members"))
    mems = db.query(Membership).filter_by(user_id=user.id).all()
    org_list = [m.org for m in mems]
    return render_template("orgs.html", orgs=org_list)

@app.route("/orgs/switch/<int:org_id>")
@require_login
def switch_org(org_id):
    db = request.db
    m = db.query(Membership).filter_by(user_id=session["user_id"], org_id=org_id).first()
    if not m: abort(403)
    session["org_id"] = org_id
    return redirect(url_for("dashboard"))

def require_admin(f):
    from functools import wraps
    @wraps(f)
    def wrap(*args, **kwargs):
        db = request.db
        m = db.query(Membership).filter_by(user_id=session["user_id"], org_id=session.get("org_id")).first()
        if not m or m.role not in ["owner","admin"]:
            abort(403)
        return f(*args, **kwargs)
    return wrap

@app.route("/orgs/members", methods=["GET","POST"])
@require_login
@require_admin
def members():
    db = request.db
    org_id = session["org_id"]
    if request.method=="POST":
        action = request.form.get("action")
        mid = int(request.form.get("mid"))
        m = db.query(Membership).filter_by(id=mid, org_id=org_id).first()
        if not m: abort(404)
        if action=="role":
            new_role = request.form.get("role")
            if new_role not in ["owner","admin","designer","viewer"]:
                flash("Invalid role.","warning")
            else:
                m.role = new_role; db.commit(); flash("Role updated.","success")
        elif action=="remove":
            db.delete(m); db.commit(); flash("Member removed.","success")
        return redirect(url_for("members"))
    mems = db.query(Membership).filter_by(org_id=org_id).all()
    return render_template("members.html", members=mems)

@app.route("/orgs/invite", methods=["GET","POST"])
@require_login
@require_admin
def invite():
    db = request.db
    if request.method=="POST":
        email = (request.form.get("email") or "").lower().strip()
        role = request.form.get("role") or "viewer"
        if role not in ["owner","admin","designer","viewer"]:
            role = "viewer"
        token = uuid.uuid4().hex
        inv = Invite(org_id=session["org_id"], email=email, role=role, token=token, created_by=session["user_id"], expires_at=datetime.datetime.utcnow()+datetime.timedelta(days=7))
        db.add(inv); db.commit()
        if BASE_URL:
            link = f"{BASE_URL}{url_for('accept_invite', token=token)}"
            send_email(email, "You're invited to Phoenix Fire CAD", f"<p>You have been invited as <b>{role}</b> to an organisation.</p><p>Accept: <a href='{link}'>Join</a></p>")
        flash("Invite created.", "success")
        return redirect(url_for("invite"))
    invs = db.query(Invite).filter_by(org_id=session["org_id"]).order_by(Invite.created_at.desc()).all()
    return render_template("invite.html", invites=invs)

@app.route("/invite/<token>", methods=["GET","POST"])
def accept_invite(token):
    db = request.db
    inv = db.query(Invite).filter_by(token=token, accepted=False).first()
    if not inv or inv.expires_at < datetime.datetime.utcnow():
        flash("Invite is invalid or expired.","danger")
        return redirect(url_for("login"))
    if "user_id" not in session:
        flash("Please log in or create an account, then revisit the invite link.","info")
        return redirect(url_for("login"))
    m = db.query(Membership).filter_by(user_id=session["user_id"], org_id=inv.org_id).first()
    if m:
        m.role = inv.role
    else:
        m = Membership(user_id=session["user_id"], org_id=inv.org_id, role=inv.role)
        db.add(m)
    inv.accepted = True
    db.commit()
    session["org_id"] = inv.org_id
    flash("You have joined the organisation.", "success")
    return redirect(url_for("dashboard"))

@app.route("/")
def home():
    if "user_id" in session: return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/dashboard")
@require_login
@require_org_member()
def dashboard():
    db = request.db
    projects = db.query(Project).filter_by(org_id=session["org_id"]).order_by(Project.updated_at.desc()).all()
    return render_template("dashboard.html", projects=projects)

@app.route("/project/new", methods=["POST"])
@require_login
@require_org_member(roles=["owner","admin","designer"])
def create_project():
    name = (request.form.get("name") or "Untitled Project").strip() or "Untitled Project"
    desc = (request.form.get("description") or "").strip()
    pid = uuid.uuid4().hex
    db = request.db
    p = Project(id=pid, org_id=session["org_id"], created_by=session["user_id"], name=name, description=desc, data_json=json.dumps({"pixels_per_meter":120,"placements":[],"zones":[]}))
    db.add(p); db.commit()
    return redirect(url_for("edit_project", project_id=pid))

@app.route("/project/<project_id>")
@require_login
@require_org_member()
def edit_project(project_id):
    db = request.db
    p = db.query(Project).filter_by(id=project_id, org_id=session["org_id"]).first()
    if not p: abort(404)
    return render_template("editor.html", project=p)

@app.route("/schematics/<project_id>")
@require_login
@require_org_member()
def schematics(project_id):
    db = request.db
    p = db.query(Project).filter_by(id=project_id, org_id=session["org_id"]).first()
    if not p: abort(404)
    return render_template("schematics.html", project=p)

@app.route("/api/projects/<project_id>", methods=["GET","PUT","DELETE"])
@require_login
@require_org_member()
def api_project(project_id):
    db = request.db
    p = db.query(Project).filter_by(id=project_id, org_id=session["org_id"]).first()
    if not p: return jsonify({"error":"not found"}), 404
    if request.method=="GET":
        return jsonify({
            "id": p.id, "name": p.name, "description": p.description,
            "data_json": p.data_json, "floorplan_path": p.floorplan_path,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None
        })
    if request.method=="PUT":
        payload = request.get_json(force=True)
        m = db.query(Membership).filter_by(user_id=session["user_id"], org_id=session["org_id"]).first()
        if m.role not in ["owner","admin","designer"]:
            return jsonify({"error":"forbidden"}), 403
        p.name = payload.get("name", p.name)
        p.description = payload.get("description", p.description)
        dj = payload.get("data_json")
        if isinstance(dj, (dict, list)): dj = json.dumps(dj)
        if dj is not None: p.data_json = dj
        p.updated_at = datetime.datetime.utcnow()
        db.commit()
        return jsonify({"ok": True})
    if request.method=="DELETE":
        m = db.query(Membership).filter_by(user_id=session["user_id"], org_id=session["org_id"]).first()
        if m.role not in ["owner","admin"]:
            return jsonify({"error":"forbidden"}), 403
        db.delete(p); db.commit()
        return jsonify({"ok": True})

@app.route("/api/projects/<project_id>/upload_floorplan", methods=["POST"])
@require_login
@require_org_member(roles=["owner","admin","designer"])
def api_upload_floorplan(project_id):
    db = request.db
    p = db.query(Project).filter_by(id=project_id, org_id=session["org_id"]).first()
    if not p: return jsonify({"error":"not found"}), 404
    file = request.files.get("file")
    if not file: return jsonify({"error":"no file"}), 400
    fname = secure_filename(file.filename)
    safe = f"{project_id}_{fname}"
    path = os.path.join(UPLOAD_DIR, safe)
    file.save(path)
    p.floorplan_path = path; p.updated_at = datetime.datetime.utcnow()
    db.commit()
    return jsonify({"ok": True, "floorplan_url": url_for('uploaded_file', filename=os.path.basename(path))})

@app.route("/uploads/<path:filename>")
@require_login
def uploaded_file(filename):
    if "org_id" not in session: abort(403)
    return send_from_directory(UPLOAD_DIR, filename)

@app.route("/api/projects/<project_id>/data", methods=["GET"])
@require_login
@require_org_member()
def api_get_data(project_id):
    db = request.db
    p = db.query(Project).filter_by(id=project_id, org_id=session["org_id"]).first()
    if not p: return jsonify({"error":"not found"}), 404
    try:
        return jsonify(json.loads(p.data_json or "{}"))
    except Exception:
        return jsonify({}), 200

application = app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","8080")), debug=False)
