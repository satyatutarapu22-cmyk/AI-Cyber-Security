from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, json
from ml_model import classify_traffic

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
DB = os.path.join(os.path.dirname(__file__), "cybersecurity.db")

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn=db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user');
    CREATE TABLE IF NOT EXISTS network_logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, src_ip TEXT, dst_ip TEXT,
      protocol TEXT, port INTEGER, packets INTEGER, bytes INTEGER,
      duration REAL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS threats(
      id INTEGER PRIMARY KEY AUTOINCREMENT, log_id INTEGER, attack_type TEXT,
      confidence REAL, severity TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS alerts(
      id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id INTEGER, message TEXT,
      status TEXT DEFAULT 'Open', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS reports(
      id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, summary TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    """)
    if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        conn.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                     ("admin", generate_password_hash("admin123"), "admin"))
        conn.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                     ("student", generate_password_hash("student123"), "user"))
    conn.commit(); conn.close()

init_db()

@app.route("/")
def home():
    if "user_id" in session: return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=request.form["username"].strip(); p=request.form["password"]
        row=db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row and check_password_hash(row["password"],p):
            session["user_id"]=row["id"]; session["username"]=row["username"]; session["role"]=row["role"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password","danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

def login_required():
    return "user_id" in session

@app.route("/dashboard")
def dashboard():
    if not login_required(): return redirect(url_for("login"))
    conn=db()
    stats={
      "logs":conn.execute("SELECT COUNT(*) c FROM network_logs").fetchone()["c"],
      "threats":conn.execute("SELECT COUNT(*) c FROM threats").fetchone()["c"],
      "alerts":conn.execute("SELECT COUNT(*) c FROM alerts WHERE status='Open'").fetchone()["c"],
      "critical":conn.execute("SELECT COUNT(*) c FROM threats WHERE severity='Critical'").fetchone()["c"]
    }
    recent=conn.execute("""SELECT n.*,t.attack_type,t.confidence,t.severity
        FROM network_logs n LEFT JOIN threats t ON n.id=t.log_id
        ORDER BY n.id DESC LIMIT 8""").fetchall()
    conn.close()
    return render_template("dashboard.html",stats=stats,recent=recent)

@app.route("/detect", methods=["GET","POST"])
def detect():
    if not login_required(): return redirect(url_for("login"))
    result=None
    if request.method=="POST":
        try:
            data={k:request.form[k] for k in ["src_ip","dst_ip","protocol"]}
            data.update({k:float(request.form[k]) for k in ["port","packets","bytes","duration"]})
            result=classify_traffic(data)
            conn=db()
            cur=conn.execute("""INSERT INTO network_logs
              (src_ip,dst_ip,protocol,port,packets,bytes,duration) VALUES(?,?,?,?,?,?,?)""",
              (data["src_ip"],data["dst_ip"],data["protocol"],int(data["port"]),
               int(data["packets"]),int(data["bytes"]),data["duration"]))
            log_id=cur.lastrowid
            tcur=conn.execute("""INSERT INTO threats(log_id,attack_type,confidence,severity)
              VALUES(?,?,?,?)""",(log_id,result["attack_type"],result["confidence"],result["severity"]))
            threat_id=tcur.lastrowid
            if result["attack_type"]!="Normal":
                conn.execute("INSERT INTO alerts(threat_id,message) VALUES(?,?)",
                             (threat_id,f"{result['severity']} alert: {result['attack_type']} traffic detected."))
            conn.commit(); conn.close()
        except Exception as e:
            flash("Please enter valid values.","danger")
    return render_template("detect.html",result=result)

@app.route("/alerts")
def alerts():
    if not login_required(): return redirect(url_for("login"))
    rows=db().execute("""SELECT a.*,t.attack_type,t.severity FROM alerts a
        JOIN threats t ON a.threat_id=t.id ORDER BY a.id DESC""").fetchall()
    return render_template("alerts.html",alerts=rows)

@app.route("/reports")
def reports():
    if not login_required(): return redirect(url_for("login"))
    conn=db()
    rows=conn.execute("""SELECT t.attack_type,t.severity,COUNT(*) count
                         FROM threats t GROUP BY t.attack_type,t.severity ORDER BY count DESC""").fetchall()
    return render_template("reports.html",rows=rows)

@app.route("/admin")
def admin():
    if session.get("role")!="admin": return redirect(url_for("dashboard"))
    conn=db()
    users=conn.execute("SELECT id,username,role FROM users ORDER BY id").fetchall()
    logs=conn.execute("SELECT * FROM network_logs ORDER BY id DESC LIMIT 20").fetchall()
    return render_template("admin.html",users=users,logs=logs)

if __name__=="__main__":
    app.run(debug=True)
