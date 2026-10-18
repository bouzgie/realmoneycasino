import os, hmac, hashlib, secrets, sqlite3, itertools, time, json
from collections import Counter
from decimal import Decimal, ROUND_DOWN
import jwt
from fastapi import FastAPI, Depends, HTTPException, Header, Request, Form
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DB = os.environ.get("DB_PATH", "casino.db")
SECRET = os.environ.get("JWT_SECRET") or secrets.token_hex(32)  # set JWT_SECRET in production
WEBHOOK_SECRET = os.environ.get("PAYMENT_WEBHOOK_SECRET", "")
MAX_BET = Decimal(os.environ.get("MAX_BET", "500"))
rng = secrets.SystemRandom()
app = FastAPI()

def db():
    c = sqlite3.connect(DB, isolation_level=None)
    c.row_factory = sqlite3.Row
    return c

def money(x): return Decimal(str(x)).quantize(Decimal("0.01"), rounding=ROUND_DOWN)

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()

def check_pw(pw, stored):
    salt, _ = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, salt), stored)

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT, pw TEXT,
        balance TEXT DEFAULT '0.00', is_admin INTEGER DEFAULT 0, created REAL);
    CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, user_id INTEGER, kind TEXT, amount TEXT, ref TEXT UNIQUE, created REAL);
    CREATE TABLE IF NOT EXISTS withdrawals(id INTEGER PRIMARY KEY, user_id INTEGER, amount TEXT, details TEXT, status TEXT DEFAULT 'pending', created REAL);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, event_name TEXT, league TEXT, odds_home REAL, odds_away REAL);
    """)
    if not c.execute("SELECT 1 FROM events").fetchone():
        c.executemany("INSERT INTO events(event_name,league,odds_home,odds_away) VALUES(?,?,?,?)",
            [("Lakers vs Celtics", "NBA", 2.0, 1.8), ("Arsenal vs Chelsea", "EPL", 2.2, 3.1), ("Yankees vs Red Sox", "MLB", 1.9, 2.0)])
    admin_user = os.environ.get("ADMIN_USERNAME", "admin")
    if not c.execute("SELECT 1 FROM users WHERE is_admin=1").fetchone():
        pw = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(14)
        c.execute("INSERT INTO users(username,email,pw,is_admin,created) VALUES(?,?,?,1,?)",
                  (admin_user, "admin@local", hash_pw(pw), time.time()))
        if not os.environ.get("ADMIN_PASSWORD"):
            with open("ADMIN_CREDENTIALS.txt", "w") as f: f.write(f"username: {admin_user}\npassword: {pw}\n")
init_db()

def user_from_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401, "Not logged in")
    try: uid = jwt.decode(authorization[7:], SECRET, algorithms=["HS256"])["uid"]
    except Exception: raise HTTPException(401, "Session expired")
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u: raise HTTPException(401, "Unknown user")
    return u

def admin_only(u=Depends(user_from_token)):
    if not u["is_admin"]: raise HTTPException(403, "Admin only")
    return u

def change_balance(c, uid, delta, kind, ref=None):
    """Atomic balance update. Raises on overdraft."""
    c.execute("BEGIN IMMEDIATE")
    try:
        bal = money(c.execute("SELECT balance FROM users WHERE id=?", (uid,)).fetchone()["balance"])
        new = bal + delta
        if new < 0: raise HTTPException(400, "Insufficient funds")
        c.execute("UPDATE users SET balance=? WHERE id=?", (str(new), uid))
        c.execute("INSERT INTO ledger(user_id,kind,amount,ref,created) VALUES(?,?,?,?,?)", (uid, kind, str(delta), ref, time.time()))
        c.execute("COMMIT")
        return new
    except Exception:
        c.execute("ROLLBACK"); raise

def settle(uid, bet, payout, kind):
    """Take the bet and pay winnings in one atomic step. Returns new balance."""
    bet = money(bet)
    if bet <= 0 or bet > MAX_BET: raise HTTPException(400, f"Bet must be between 0.01 and {MAX_BET}")
    c = db()
    c.execute("BEGIN IMMEDIATE")
    try:
        bal = money(c.execute("SELECT balance FROM users WHERE id=?", (uid,)).fetchone()["balance"])
        if bal < bet: raise HTTPException(400, "Insufficient funds")
        new = bal - bet + payout
        c.execute("UPDATE users SET balance=? WHERE id=?", (str(new), uid))
        c.execute("INSERT INTO ledger(user_id,kind,amount,created) VALUES(?,?,?,?)", (uid, kind, str(payout - bet), time.time()))
        c.execute("COMMIT")
        return new
    except Exception:
        c.execute("ROLLBACK"); raise

# ---------- auth ----------
class Reg(BaseModel):
    username: str = Field(min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]+$")
    email: str = Field(max_length=100)
    password: str = Field(min_length=8, max_length=100)

@app.post("/register")
def register(r: Reg):
    try:
        db().execute("INSERT INTO users(username,email,pw,created) VALUES(?,?,?,?)", (r.username, r.email, hash_pw(r.password), time.time()))
    except sqlite3.IntegrityError: raise HTTPException(400, "Username taken")
    return {"ok": True}

attempts = {}
@app.post("/token")
def token(request: Request, username: str = Form(...), password: str = Form(...)):
    key = (request.client.host, username); now = time.time()
    attempts[key] = [t for t in attempts.get(key, []) if now - t < 300]
    if len(attempts[key]) >= 5: raise HTTPException(429, "Too many attempts, wait 5 minutes")
    u = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or not check_pw(password, u["pw"]):
        attempts[key].append(now); raise HTTPException(401, "Wrong username or password")
    return {"access_token": jwt.encode({"uid": u["id"], "exp": now + 8 * 3600}, SECRET, algorithm="HS256"), "balance": float(u["balance"])}

@app.get("/profile")
def profile(u=Depends(user_from_token)):
    return {"username": u["username"], "balance": float(u["balance"]), "is_admin": bool(u["is_admin"])}

# ---------- games (all outcomes decided here, never by the browser) ----------
@app.post("/slots/spin")
def spin(game_name: str = Form(...), bet_amount: float = Form(...), u=Depends(user_from_token)):
    cfg = {"cherry": (Decimal("2.0"), 0.47, ["🍒", "🍋", "🔔"]), "diamond": (Decimal("5.0"), 0.19, ["💎", "7️⃣", "⭐"])}.get(game_name)
    if not cfg: raise HTTPException(400, "Unknown game")
    mult, p, symbols = cfg
    bet = money(bet_amount)
    won = rng.random() < p
    results = [symbols[0]] * 3 if won else rng.sample(symbols, 3)
    win = money(bet * mult) if won else Decimal("0.00")
    bal = settle(u["id"], bet, win, "slots")
    return {"results": results, "win_amount": float(win), "balance": float(bal)}

R = "23456789TJQKA"
ORDER = ["royal", "sf", "quads", "fh", "flush", "straight", "trips", "twopair", "pair", "high"]
PAY = {"royal": 100, "sf": 50, "quads": 20, "fh": 7, "flush": 5, "straight": 4, "trips": 3, "twopair": 1, "pair": 0, "high": 0}
NAMES = {"royal": "Royal Flush", "sf": "Straight Flush", "quads": "Four of a Kind", "fh": "Full House", "flush": "Flush",
         "straight": "Straight", "trips": "Three of a Kind", "twopair": "Two Pair", "pair": "Pair", "high": "High Card"}

def rank5(c):
    v = sorted([R.index(x[0]) for x in c], reverse=True); s = len({x[1] for x in c}) == 1
    cnt = Counter(v); g = sorted(cnt.values(), reverse=True)
    st = len(cnt) == 5 and (v[0] - v[4] == 4 or v == [12, 3, 2, 1, 0])
    if st and s: return "royal" if v[0] == 12 and v[1] == 11 else "sf"
    if g[0] == 4: return "quads"
    if g == [3, 2]: return "fh"
    if s: return "flush"
    if st: return "straight"
    if g[0] == 3: return "trips"
    if g[:2] == [2, 2]: return "twopair"
    if g[0] == 2: return "pair"
    return "high"

class PokerReq(BaseModel):
    amount: float

@app.post("/poker")
def poker(r: PokerReq, u=Depends(user_from_token)):
    deck = [a + b for a in R for b in "HDCS"]
    cards = rng.sample(deck, 7)
    best = min((rank5(x) for x in itertools.combinations(cards, 5)), key=ORDER.index)
    bet = money(r.amount); mult = PAY[best]
    win = money(bet * mult)
    bal = settle(u["id"], bet, win, "poker")
    status = "WIN" if mult > 1 else ("PUSH" if mult == 1 else "LOSE")
    return {"cards": cards, "hand_name": NAMES[best], "status": status, "winnings": float(win), "balance": float(bal)}

@app.get("/sports/events")
def events():
    return [dict(r) for r in db().execute("SELECT * FROM events")]

class BetReq(BaseModel):
    event_id: int
    selection: str
    amount: float

@app.post("/sports/bet")
def sports_bet(r: BetReq, u=Depends(user_from_token)):
    e = db().execute("SELECT * FROM events WHERE id=?", (r.event_id,)).fetchone()
    if not e or r.selection not in ("Home", "Away"): raise HTTPException(400, "Bad bet")
    odds = Decimal(str(e["odds_home" if r.selection == "Home" else "odds_away"]))
    # Simulated result with a 5% house margin. Replace with a real results feed before going live.
    won = rng.random() < float(Decimal("0.95") / odds)
    bet = money(r.amount); win = money(bet * odds) if won else Decimal("0.00")
    bal = settle(u["id"], bet, win, "sports")
    return {"status": "WIN" if won else "LOSE", "winnings": float(win), "balance": float(bal)}

# ---------- wallet / payments ----------
@app.post("/payments/webhook")
async def webhook(request: Request, x_signature: str = Header("")):
    """Payment processor calls this when a deposit is confirmed. Signed with PAYMENT_WEBHOOK_SECRET (HMAC-SHA256)."""
    body = await request.body()
    if not WEBHOOK_SECRET or not hmac.compare_digest(hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest(), x_signature):
        raise HTTPException(401, "Bad signature")
    ev = json.loads(body)  # {"event_id": "...", "username": "...", "amount": 50.00}
    c = db(); u = c.execute("SELECT id FROM users WHERE username=?", (ev["username"],)).fetchone()
    if not u: raise HTTPException(404, "No such user")
    try: change_balance(c, u["id"], money(ev["amount"]), "deposit", "dep:" + ev["event_id"])
    except sqlite3.IntegrityError: pass  # duplicate event, already credited
    return {"ok": True}

class WdReq(BaseModel):
    amount: float
    details: str = Field(max_length=300)

@app.post("/wallet/withdraw")
def withdraw(r: WdReq, u=Depends(user_from_token)):
    amt = money(r.amount)
    if amt <= 0: raise HTTPException(400, "Invalid amount")
    c = db(); bal = change_balance(c, u["id"], -amt, "withdraw_hold")
    c.execute("INSERT INTO withdrawals(user_id,amount,details,created) VALUES(?,?,?,?)", (u["id"], str(amt), r.details, time.time()))
    return {"balance": float(bal), "status": "pending"}

# ---------- admin ----------
@app.get("/admin/dashboard")
def admin_dash(a=Depends(admin_only)):
    c = db()
    return {"total_users": c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"],
            "total_transactions": c.execute("SELECT COUNT(*) n FROM ledger").fetchone()["n"],
            "users": [{"username": r["username"], "balance": r["balance"]} for r in c.execute("SELECT username,balance FROM users ORDER BY id")],
            "withdrawals": [dict(r) for r in c.execute("SELECT w.id,u.username,w.amount,w.details,w.status FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.status='pending'")]}

class CreditReq(BaseModel):
    username: str
    amount: float

@app.post("/admin/credit")
def admin_credit(r: CreditReq, a=Depends(admin_only)):
    c = db(); u = c.execute("SELECT id FROM users WHERE username=?", (r.username,)).fetchone()
    if not u: raise HTTPException(404, "No such user")
    return {"balance": float(change_balance(c, u["id"], money(r.amount), "admin_credit"))}

@app.post("/admin/withdrawals/{wid}/{action}")
def admin_wd(wid: int, action: str, a=Depends(admin_only)):
    c = db(); w = c.execute("SELECT * FROM withdrawals WHERE id=? AND status='pending'", (wid,)).fetchone()
    if not w or action not in ("approve", "reject"): raise HTTPException(400, "Bad request")
    if action == "reject": change_balance(c, w["user_id"], money(w["amount"]), "withdraw_refund")
    c.execute("UPDATE withdrawals SET status=? WHERE id=?", ("paid" if action == "approve" else "rejected", wid))
    return {"ok": True}

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def home(): return FileResponse("index.html")
