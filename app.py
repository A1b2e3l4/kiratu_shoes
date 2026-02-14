"""
Kiratu's Shoes – Flask Web Application  (pure SQLite, no SQLAlchemy)
Run with: python3 app.py
"""
import os, re, sqlite3, random, string, smtplib, secrets
from datetime import datetime, timedelta
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, redirect, url_for, request, flash, session, make_response, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ── APP ──
app = Flask(__name__)
app.config['SECRET_KEY'] = 'kiratu_shoes_secret_2024_!@#$%KE'
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'kiratu.db')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'kiratushoes@gmail.com'
app.config['MAIL_PASSWORD'] = 'udqg vgbj rfym ewvl'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# ── DB ──
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e): g.pop('db', None) and None

def qdb(sql, args=(), one=False, commit=False):
    db = get_db()
    cur = db.execute(sql, args)
    if commit:
        db.commit()
        return cur.lastrowid
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def init_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL, last_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        is_verified INTEGER DEFAULT 0, is_admin INTEGER DEFAULT 0,
        created_at TEXT DEFAULT(datetime('now')));
    CREATE TABLE IF NOT EXISTS shoes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_path TEXT NOT NULL, size TEXT NOT NULL, price REAL NOT NULL,
        is_available INTEGER DEFAULT 1,
        created_at TEXT DEFAULT(datetime('now')));
    CREATE TABLE IF NOT EXISTS ads(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_path TEXT NOT NULL, link TEXT, is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT(datetime('now')));
    CREATE TABLE IF NOT EXISTS email_verification(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        code TEXT NOT NULL, expiry_time TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS password_reset(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token TEXT UNIQUE NOT NULL, expiry_time TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS activity_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER REFERENCES users(id),
        action TEXT NOT NULL, timestamp TEXT DEFAULT(datetime('now')));
    CREATE TABLE IF NOT EXISTS app_settings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mpesa_till TEXT DEFAULT '0000000',
        whatsapp_link TEXT DEFAULT 'https://wa.me/254107045642',
        about_text TEXT DEFAULT 'Welcome to Kiratu''s Shoes – quality mutumba shoes at great prices.',
        show_sold_shoes INTEGER DEFAULT 1,
        primary_color TEXT DEFAULT '#c8a96e',
        accent_color TEXT DEFAULT '#1a1a2e');
    """)
    db.commit()
    e = db.execute("SELECT id FROM users WHERE email='kiratushoes@gmail.com'").fetchone()
    if not e:
        db.execute("INSERT INTO users(first_name,last_name,email,password_hash,is_verified,is_admin) VALUES(?,?,?,?,1,1)",
            ('Kiratu','Admin','kiratushoes@gmail.com',generate_password_hash('Admin@1234')))
        db.commit()
        print("[✓] Default admin created: kiratushoes@gmail.com / Admin@1234")
    if not db.execute("SELECT id FROM app_settings").fetchone():
        db.execute("INSERT INTO app_settings(id) VALUES(1)")
        db.commit()
    db.close()
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'],'shoes'),exist_ok=True)
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'],'ads'),exist_ok=True)

# ── HELPERS ──
def allowed_file(fn): return '.' in fn and fn.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def send_email(to, subject, html):
    try:
        msg=MIMEMultipart('alternative'); msg['Subject']=subject
        msg['From']=app.config['MAIL_USERNAME']; msg['To']=to
        msg.attach(MIMEText(html,'html'))
        with smtplib.SMTP(app.config['MAIL_SERVER'],app.config['MAIL_PORT']) as s:
            s.starttls(); s.login(app.config['MAIL_USERNAME'],app.config['MAIL_PASSWORD'])
            s.sendmail(app.config['MAIL_USERNAME'],to,msg.as_string())
        return True
    except Exception as ex:
        app.logger.error(f"Email error: {ex}"); return False

def gen_code(): return ''.join(random.choices(string.digits,k=6))

def log_action(admin_id, action):
    qdb("INSERT INTO activity_logs(admin_id,action) VALUES(?,?)",(admin_id,action),commit=True)

def get_settings():
    s=qdb("SELECT * FROM app_settings LIMIT 1",one=True)
    if not s:
        qdb("INSERT INTO app_settings(id) VALUES(1)",commit=True)
        s=qdb("SELECT * FROM app_settings LIMIT 1",one=True)
    return s

def cur_user():
    uid=session.get('user_id')
    return qdb("SELECT * FROM users WHERE id=?", (uid,),one=True) if uid else None

def pw_strength(p):
    if len(p)<8: return 'weak'
    s=sum([bool(re.search(r,p)) for r in [r'[A-Z]',r'[a-z]',r'\d',r'[!@#$%^&*]']])
    return 'weak' if s<=2 else 'medium' if s==3 else 'strong'

def save_file(file,sub):
    ext=secure_filename(file.filename).rsplit('.',1)[1].lower()
    name=secrets.token_hex(8)+'.'+ext
    folder=os.path.join(app.config['UPLOAD_FOLDER'],sub)
    os.makedirs(folder,exist_ok=True)
    file.save(os.path.join(folder,name))
    return os.path.join('uploads',sub,name).replace('\\','/')

def pdt(v):
    if not v: return datetime.utcnow()
    if isinstance(v,datetime): return v
    for f in ('%Y-%m-%d %H:%M:%S','%Y-%m-%dT%H:%M:%S'):
        try: return datetime.strptime(str(v),f)
        except: pass
    return datetime.utcnow()

def is_new(created_at): return (datetime.utcnow()-pdt(created_at)).days<=7

# ── DECORATORS ──
def login_req(f):
    @wraps(f)
    def d(*a,**k):
        if not session.get('user_id'): flash('Please log in.','warning'); return redirect(url_for('login'))
        return f(*a,**k)
    return d

def admin_req(f):
    @wraps(f)
    def d(*a,**k):
        u=cur_user()
        if not u or not u['is_admin']: flash('Admin required.','danger'); return redirect(url_for('home'))
        return f(*a,**k)
    return d

# ── CONTEXT ──
@app.context_processor
def ctx():
    settings=get_settings()
    ads=qdb("SELECT * FROM ads WHERE is_active=1 ORDER BY created_at DESC")
    return dict(current_user=cur_user(),settings=settings,theme=request.cookies.get('theme','light'),
        active_ads=ads,is_new_shoe=is_new,pdt=pdt)

@app.template_filter('fmtp')
def fmtp(v):
    try: return f"{float(v):,.0f}"
    except: return str(v)

@app.template_filter('fmtd')
def fmtd(v): return pdt(v).strftime('%B %d, %Y')

@app.template_filter('fmtdt')
def fmtdt(v): return pdt(v).strftime('%b %d, %Y %H:%M')

# ── PUBLIC ──
@app.route('/')
def home():
    s=get_settings()
    if s and s['show_sold_shoes']: shoes=qdb("SELECT * FROM shoes ORDER BY created_at DESC")
    else: shoes=qdb("SELECT * FROM shoes WHERE is_available=1 ORDER BY created_at DESC")
    recent=qdb("SELECT * FROM shoes WHERE is_available=1 ORDER BY created_at DESC LIMIT 4")
    return render_template('home.html',shoes=shoes,recent_shoes=recent)

@app.route('/shoe/<int:shoe_id>')
def shoe_detail(shoe_id):
    shoe=qdb("SELECT * FROM shoes WHERE id=?", (shoe_id,),one=True)
    if not shoe: flash('Not found.','danger'); return redirect(url_for('home'))
    return render_template('shoe_detail.html',shoe=shoe,settings=get_settings())

@app.route('/about')
def about(): return render_template('about.html')

@app.route('/contact')
def contact(): return render_template('contact.html')

# ── AUTH ──
@app.route('/register',methods=['GET','POST'])
def register():
    if session.get('user_id'): return redirect(url_for('dashboard'))
    if request.method=='POST':
        fn=request.form.get('first_name','').strip(); ln=request.form.get('last_name','').strip()
        em=request.form.get('email','').strip().lower(); pw=request.form.get('password','')
        cf=request.form.get('confirm_password','')
        if not all([fn,ln,em,pw,cf]): flash('All fields required.','danger'); return render_template('auth/register.html')
        if pw!=cf: flash('Passwords do not match.','danger'); return render_template('auth/register.html')
        if pw_strength(pw)=='weak': flash('Password too weak (8+ chars, upper, lower, number).','danger'); return render_template('auth/register.html')
        if qdb("SELECT id FROM users WHERE email=?",(em,),one=True): flash('Email already registered.','danger'); return render_template('auth/register.html')
        uid=qdb("INSERT INTO users(first_name,last_name,email,password_hash) VALUES(?,?,?,?)",(fn,ln,em,generate_password_hash(pw)),commit=True)
        code=gen_code(); exp=(datetime.utcnow()+timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        qdb("INSERT INTO email_verification(user_id,code,expiry_time) VALUES(?,?,?)",(uid,code,exp),commit=True)
        html=f"<div style='font-family:Arial;padding:20px'><h2 style='color:#c8a96e'>Kiratu's Shoes</h2><p>Hello {fn}, your verification code:</p><h1 style='letter-spacing:8px;color:#1a1a2e'>{code}</h1><p>Expires in 1 hour.</p></div>"
        if not send_email(em,"Verify your Kiratu's Shoes account",html): flash('Account created but email failed. Use Resend Verification.','warning')
        session['pending_verify_user_id']=uid
        flash('Account created! Check your email for the verification code.','success')
        return redirect(url_for('verify_email'))
    return render_template('auth/register.html')

@app.route('/verify-email',methods=['GET','POST'])
def verify_email():
    uid=session.get('pending_verify_user_id')
    if not uid: return redirect(url_for('login'))
    user=qdb("SELECT * FROM users WHERE id=?",(uid,),one=True)
    if request.method=='POST':
        code=request.form.get('code','').strip()
        rec=qdb("SELECT * FROM email_verification WHERE user_id=? AND code=?",(uid,code),one=True)
        if not rec: flash('Invalid code.','danger'); return render_template('auth/verify_email.html',user=user)
        if datetime.utcnow()>pdt(rec['expiry_time']): flash('Code expired. Request a new one.','danger'); return render_template('auth/verify_email.html',user=user)
        qdb("UPDATE users SET is_verified=1 WHERE id=?",(uid,),commit=True)
        qdb("DELETE FROM email_verification WHERE id=?",(rec['id'],),commit=True)
        session.pop('pending_verify_user_id',None)
        flash('Email verified! You can now log in.','success')
        return redirect(url_for('login'))
    return render_template('auth/verify_email.html',user=user)

@app.route('/resend-verification',methods=['GET','POST'])
def resend_verification():
    if request.method=='POST':
        em=request.form.get('email','').strip().lower()
        u=qdb("SELECT * FROM users WHERE email=? AND is_verified=0",(em,),one=True)
        if u:
            qdb("DELETE FROM email_verification WHERE user_id=?",(u['id'],),commit=True)
            code=gen_code(); exp=(datetime.utcnow()+timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            qdb("INSERT INTO email_verification(user_id,code,expiry_time) VALUES(?,?,?)",(u['id'],code,exp),commit=True)
            html=f"<div style='font-family:Arial;padding:20px'><h2 style='color:#c8a96e'>New Verification Code</h2><p>Hello {u['first_name']},</p><h1 style='letter-spacing:8px;color:#1a1a2e'>{code}</h1><p>Expires in 1 hour.</p></div>"
            send_email(em,"New Code – Kiratu's Shoes",html)
            session['pending_verify_user_id']=u['id']
        flash('If registered and unverified, a new code was sent.','info')
        return redirect(url_for('verify_email'))
    return render_template('auth/resend_verification.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if session.get('user_id'): return redirect(url_for('dashboard'))
    if request.method=='POST':
        em=request.form.get('email','').strip().lower(); pw=request.form.get('password','')
        rem=request.form.get('remember')
        u=qdb("SELECT * FROM users WHERE email=?",(em,),one=True)
        if not u or not check_password_hash(u['password_hash'],pw): flash('Invalid email or password.','danger'); return render_template('auth/login.html')
        if not u['is_verified']: session['pending_verify_user_id']=u['id']; flash('Please verify your email first.','warning'); return redirect(url_for('verify_email'))
        session['user_id']=u['id']; session.permanent=bool(rem)
        flash(f"Welcome back, {u['first_name']}!",'success')
        return redirect(url_for('admin_dashboard') if u['is_admin'] else url_for('dashboard'))
    return render_template('auth/login.html')

@app.route('/logout')
def logout(): session.clear(); flash('Logged out.','info'); return redirect(url_for('home'))

@app.route('/forgot-password',methods=['GET','POST'])
def forgot_password():
    if request.method=='POST':
        em=request.form.get('email','').strip().lower()
        u=qdb("SELECT * FROM users WHERE email=?",(em,),one=True)
        if u:
            qdb("DELETE FROM password_reset WHERE user_id=?",(u['id'],),commit=True)
            tok=secrets.token_urlsafe(40); exp=(datetime.utcnow()+timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')
            qdb("INSERT INTO password_reset(user_id,token,expiry_time) VALUES(?,?,?)",(u['id'],tok,exp),commit=True)
            reset_url=url_for('reset_password',token=tok,_external=True)
            html=f"<div style='font-family:Arial;padding:20px'><h2 style='color:#c8a96e'>Password Reset</h2><p>Hello {u['first_name']},</p><a href='{reset_url}' style='display:inline-block;background:#c8a96e;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none'>Reset Password</a><p>Expires in 2 hours.</p></div>"
            send_email(em,"Password Reset – Kiratu's Shoes",html)
        flash('If registered, a reset link has been sent.','info')
    return render_template('auth/forgot_password.html')

@app.route('/reset-password/<token>',methods=['GET','POST'])
def reset_password(token):
    rec=qdb("SELECT * FROM password_reset WHERE token=?",(token,),one=True)
    if not rec: flash('Invalid reset link.','danger'); return redirect(url_for('forgot_password'))
    if datetime.utcnow()>pdt(rec['expiry_time']):
        qdb("DELETE FROM password_reset WHERE id=?",(rec['id'],),commit=True)
        flash('Link expired.','danger'); return redirect(url_for('forgot_password'))
    if request.method=='POST':
        pw=request.form.get('password',''); cf=request.form.get('confirm_password','')
        if pw!=cf: flash('Passwords do not match.','danger'); return render_template('auth/reset_password.html',token=token)
        if pw_strength(pw)=='weak': flash('Password too weak.','danger'); return render_template('auth/reset_password.html',token=token)
        qdb("UPDATE users SET password_hash=? WHERE id=?",(generate_password_hash(pw),rec['user_id']),commit=True)
        qdb("DELETE FROM password_reset WHERE id=?",(rec['id'],),commit=True)
        flash('Password reset! Please log in.','success'); return redirect(url_for('login'))
    return render_template('auth/reset_password.html',token=token)

# ── USER ──
@app.route('/dashboard')
@login_req
def dashboard():
    u=cur_user()
    if u['is_admin']: return redirect(url_for('admin_dashboard'))
    recent=qdb("SELECT * FROM shoes WHERE is_available=1 ORDER BY created_at DESC LIMIT 6")
    return render_template('user/dashboard.html',user=u,recent_shoes=recent)

@app.route('/profile')
@login_req
def profile(): return render_template('user/profile.html',user=cur_user())

@app.route('/edit-profile',methods=['GET','POST'])
@login_req
def edit_profile():
    u=cur_user()
    if request.method=='POST':
        qdb("UPDATE users SET first_name=?,last_name=? WHERE id=?",(request.form.get('first_name','').strip(),request.form.get('last_name','').strip(),u['id']),commit=True)
        flash('Profile updated!','success'); return redirect(url_for('profile'))
    return render_template('user/edit_profile.html',user=u)

@app.route('/change-password',methods=['GET','POST'])
@login_req
def change_password():
    u=cur_user()
    if request.method=='POST':
        cur=request.form.get('current_password',''); nw=request.form.get('new_password',''); cf=request.form.get('confirm_password','')
        if not check_password_hash(u['password_hash'],cur): flash('Current password incorrect.','danger'); return render_template('user/change_password.html')
        if nw!=cf: flash('New passwords do not match.','danger'); return render_template('user/change_password.html')
        if pw_strength(nw)=='weak': flash('Password too weak.','danger'); return render_template('user/change_password.html')
        qdb("UPDATE users SET password_hash=? WHERE id=?",(generate_password_hash(nw),u['id']),commit=True)
        flash('Password changed!','success'); return redirect(url_for('profile'))
    return render_template('user/change_password.html')

@app.route('/set-theme/<theme>')
def set_theme(theme):
    if theme not in ('light','dark'): theme='light'
    resp=make_response(redirect(request.referrer or url_for('home')))
    resp.set_cookie('theme',theme,max_age=60*60*24*365)
    return resp

# ── ADMIN ──
@app.route('/admin')
@admin_req
def admin_dashboard():
    total=qdb("SELECT COUNT(*) as c FROM shoes",one=True)['c']
    avail=qdb("SELECT COUNT(*) as c FROM shoes WHERE is_available=1",one=True)['c']
    sold=qdb("SELECT COUNT(*) as c FROM shoes WHERE is_available=0",one=True)['c']
    tusers=qdb("SELECT COUNT(*) as c FROM users",one=True)['c']
    val=qdb("SELECT SUM(price) as s FROM shoes WHERE is_available=1",one=True)
    tval=val['s'] if val and val['s'] else 0
    logs=qdb("SELECT l.*,u.first_name,u.last_name FROM activity_logs l JOIN users u ON l.admin_id=u.id ORDER BY l.timestamp DESC LIMIT 10")
    return render_template('admin/dashboard.html',total_shoes=total,available_shoes=avail,sold_shoes=sold,total_users=tusers,total_value=tval,logs=logs)

@app.route('/admin/shoes')
@admin_req
def admin_shoes(): return render_template('admin/shoes.html',shoes=qdb("SELECT * FROM shoes ORDER BY created_at DESC"))

@app.route('/admin/shoes/add',methods=['GET','POST'])
@admin_req
def admin_add_shoe():
    if request.method=='POST':
        img=request.files.get('image'); size=request.form.get('size','').strip(); price=request.form.get('price','0')
        if not img or not allowed_file(img.filename): flash('Valid image required.','danger'); return render_template('admin/add_shoe.html')
        if not size: flash('Size required.','danger'); return render_template('admin/add_shoe.html')
        try: price=float(price)
        except: flash('Invalid price.','danger'); return render_template('admin/add_shoe.html')
        path=save_file(img,'shoes')
        qdb("INSERT INTO shoes(image_path,size,price) VALUES(?,?,?)",(path,size,price),commit=True)
        log_action(session['user_id'],f'Added shoe: Size {size}, KES {price}')
        flash('Shoe added!','success'); return redirect(url_for('admin_shoes'))
    return render_template('admin/add_shoe.html')

@app.route('/admin/shoes/<int:sid>/toggle',methods=['POST'])
@admin_req
def admin_toggle_shoe(sid):
    s=qdb("SELECT * FROM shoes WHERE id=?",(sid,),one=True)
    if not s: flash('Not found.','danger'); return redirect(url_for('admin_shoes'))
    ns=0 if s['is_available'] else 1
    qdb("UPDATE shoes SET is_available=? WHERE id=?",(ns,sid),commit=True)
    log_action(session['user_id'],f"Marked shoe #{sid} as {'available' if ns else 'sold'}")
    flash(f"Shoe marked as {'available' if ns else 'sold'}.","success"); return redirect(url_for('admin_shoes'))

@app.route('/admin/shoes/<int:sid>/delete',methods=['POST'])
@admin_req
def admin_delete_shoe(sid):
    s=qdb("SELECT * FROM shoes WHERE id=?",(sid,),one=True)
    if not s: flash('Not found.','danger'); return redirect(url_for('admin_shoes'))
    fp=os.path.join('static',s['image_path'])
    if os.path.exists(fp): os.remove(fp)
    qdb("DELETE FROM shoes WHERE id=?",(sid,),commit=True)
    log_action(session['user_id'],f'Deleted shoe #{sid}')
    flash('Shoe deleted.','info'); return redirect(url_for('admin_shoes'))

@app.route('/admin/users')
@admin_req
def admin_users(): return render_template('admin/users.html',users=qdb("SELECT * FROM users ORDER BY created_at DESC"))

@app.route('/admin/users/<int:uid>')
@admin_req
def admin_user_detail(uid):
    u=qdb("SELECT * FROM users WHERE id=?",(uid,),one=True)
    if not u: flash('Not found.','danger'); return redirect(url_for('admin_users'))
    return render_template('admin/user_detail.html',user=u)

@app.route('/admin/users/<int:uid>/delete',methods=['POST'])
@admin_req
def admin_delete_user(uid):
    u=qdb("SELECT * FROM users WHERE id=?",(uid,),one=True)
    if not u: flash('Not found.','danger'); return redirect(url_for('admin_users'))
    if u['email']=='kiratushoes@gmail.com': flash('Cannot delete default admin.','danger'); return redirect(url_for('admin_users'))
    qdb("DELETE FROM users WHERE id=?",(uid,),commit=True)
    log_action(session['user_id'],f"Deleted user: {u['email']}")
    flash('User deleted.','info'); return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:uid>/promote',methods=['POST'])
@admin_req
def admin_promote_user(uid):
    u=qdb("SELECT * FROM users WHERE id=?",(uid,),one=True)
    if not u: flash('Not found.','danger'); return redirect(url_for('admin_users'))
    qdb("UPDATE users SET is_admin=1 WHERE id=?",(uid,),commit=True)
    log_action(session['user_id'],f"Promoted: {u['email']}")
    flash(f"{u['first_name']} promoted to admin.",'success'); return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:uid>/demote',methods=['POST'])
@admin_req
def admin_demote_user(uid):
    u=qdb("SELECT * FROM users WHERE id=?",(uid,),one=True)
    if not u: flash('Not found.','danger'); return redirect(url_for('admin_users'))
    if u['email']=='kiratushoes@gmail.com': flash('Cannot demote default admin.','danger'); return redirect(url_for('admin_users'))
    qdb("UPDATE users SET is_admin=0 WHERE id=?",(uid,),commit=True)
    log_action(session['user_id'],f"Demoted: {u['email']}")
    flash(f"{u['first_name']} demoted.",'info'); return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:uid>/reset-password',methods=['POST'])
@admin_req
def admin_reset_user_password(uid):
    u=qdb("SELECT * FROM users WHERE id=?",(uid,),one=True)
    if not u: flash('Not found.','danger'); return redirect(url_for('admin_users'))
    np=secrets.token_urlsafe(10)
    qdb("UPDATE users SET password_hash=? WHERE id=?",(generate_password_hash(np),uid),commit=True)
    html=f"<div style='font-family:Arial;padding:20px'><h2 style='color:#c8a96e'>Password Reset by Admin</h2><p>Hello {u['first_name']}, your new temporary password: <strong>{np}</strong></p><p>Please log in and change it.</p></div>"
    send_email(u['email'],"Password Reset – Kiratu's Shoes",html)
    log_action(session['user_id'],f"Reset password for: {u['email']}")
    flash(f"Password reset and emailed.",'success'); return redirect(url_for('admin_user_detail',uid=uid))

@app.route('/admin/ads')
@admin_req
def admin_ads(): return render_template('admin/ads.html',ads=qdb("SELECT * FROM ads ORDER BY created_at DESC"))

@app.route('/admin/ads/add',methods=['POST'])
@admin_req
def admin_add_ad():
    img=request.files.get('image'); link=request.form.get('link','').strip()
    if not img or not allowed_file(img.filename): flash('Valid image required.','danger'); return redirect(url_for('admin_ads'))
    path=save_file(img,'ads')
    qdb("INSERT INTO ads(image_path,link) VALUES(?,?)",(path,link or None),commit=True)
    log_action(session['user_id'],'Added new advertisement')
    flash('Ad added!','success'); return redirect(url_for('admin_ads'))

@app.route('/admin/ads/<int:aid>/toggle',methods=['POST'])
@admin_req
def admin_toggle_ad(aid):
    a=qdb("SELECT * FROM ads WHERE id=?",(aid,),one=True)
    if not a: flash('Not found.','danger'); return redirect(url_for('admin_ads'))
    qdb("UPDATE ads SET is_active=? WHERE id=?",(0 if a['is_active'] else 1, aid),commit=True)
    flash('Ad status updated.','success'); return redirect(url_for('admin_ads'))

@app.route('/admin/ads/<int:aid>/delete',methods=['POST'])
@admin_req
def admin_delete_ad(aid):
    a=qdb("SELECT * FROM ads WHERE id=?",(aid,),one=True)
    if not a: flash('Not found.','danger'); return redirect(url_for('admin_ads'))
    fp=os.path.join('static',a['image_path'])
    if os.path.exists(fp): os.remove(fp)
    qdb("DELETE FROM ads WHERE id=?",(aid,),commit=True)
    log_action(session['user_id'],f'Deleted ad #{aid}')
    flash('Ad deleted.','info'); return redirect(url_for('admin_ads'))

@app.route('/admin/settings',methods=['GET','POST'])
@admin_req
def admin_settings():
    s=get_settings()
    if request.method=='POST':
        qdb("UPDATE app_settings SET mpesa_till=?,whatsapp_link=?,about_text=?,show_sold_shoes=?,primary_color=?,accent_color=? WHERE id=?",
            (request.form.get('mpesa_till','').strip(),request.form.get('whatsapp_link','').strip(),
             request.form.get('about_text',''),1 if request.form.get('show_sold_shoes') else 0,
             request.form.get('primary_color','#c8a96e'),request.form.get('accent_color','#1a1a2e'),s['id']),commit=True)
        log_action(session['user_id'],'Updated business settings')
        flash('Settings saved!','success'); return redirect(url_for('admin_settings'))
    return render_template('admin/settings.html',settings=s)

@app.route('/admin/logs')
@admin_req
def admin_logs():
    logs=qdb("SELECT l.*,u.first_name,u.last_name FROM activity_logs l JOIN users u ON l.admin_id=u.id ORDER BY l.timestamp DESC LIMIT 100")
    return render_template('admin/logs.html',logs=logs)

@app.route('/admin/stk', methods=['GET'])
@admin_req
def admin_stk_page():
    return render_template('admin/stk.html')

@app.route('/admin/stk', methods=['POST'])
@admin_req
def stk():
    phone = request.form['phone']
    amount = request.form['amount']
    reference = request.form.get('reference', 'Kiratu Shoes')
    note = request.form.get('note', '')

    # TODO: call MPesa API here

    flash(f"STK Push sent to {phone} for KES {amount}", "success")
    return redirect(url_for('admin/stk.html'))

# ── RUN ──
if __name__=='__main__':
    with app.app_context():
        init_db()
    print("\n"+"="*55)
    print("  👟  Kiratu's Shoes is RUNNING!")
    print("  Visit:   http://127.0.0.1:5000")
    print("  Admin:   http://127.0.0.1:5000/admin")
    print("  Login:   kiratushoes@gmail.com / Admin@1234")
    print("="*55+"\n")
    app.run(debug=True,host='0.0.0.0',port=5000)
