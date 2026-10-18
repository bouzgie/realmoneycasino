import base64, hashlib, hmac, itertools, json, os, secrets, sqlite3, time
from collections import Counter
from contextlib import closing
from fastapi import Depends, FastAPI, Form, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field

DB = os.environ.get("DB_PATH", "casino.db")
SECRET = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "").strip().lower()
START_BALANCE = 1000.0  # PLAY MONEY ONLY
MAX_BET = 500.0
rng = secrets.SystemRandom()
app = FastAPI(title="WormGPT Casino (play money)")
oauth = OAuth2PasswordBearer(tokenUrl="token")


def db():
    c = sqlite3.connect(DB, isolation_level=None)
    c.row_factory = sqlite3.Row
    return c


with closing(db()) as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT,
        pw TEXT, balance REAL, is_admin INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY, user_id INT, kind TEXT,
        bet REAL, payout REAL, ts REAL);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, event_name TEXT, league TEXT,
        odds_home REAL, odds_away REAL);""")
    if not c.execute("SELECT 1 FROM events").fetchone():
        c.executemany("INSERT INTO events(event_name,league,odds_home,odds_away) VALUES(?,?,?,?)", [
            ("Lakers vs Celtics", "NBA", 1.9, 2.0), ("Real Madrid vs Barcelona", "La Liga", 2.2, 2.6),
            ("Chiefs vs Bills", "NFL", 1.8, 2.1)])


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + ":" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def check_pw(pw, stored):
    salt, h = stored.split(":")
    return hmac.compare_digest(hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex(), h)


def make_token(uid):
    body = base64.urlsafe_b64encode(json.dumps({"uid": uid, "exp": time.time() + 86400}).encode()).decode()
    return body + "." + hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()


def current_user(token: str = Depends(oauth)):
    try:
        body, sig = token.split(".")
        if not hmac.compare_digest(sig, hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()):
            raise ValueError
        data = json.loads(base64.urlsafe_b64decode(body))
        if data["exp"] < time.time():
            raise ValueError
    except Exception:
        raise HTTPException(401, "Invalid or expired session")
    with closing(db()) as c:
        u = c.execute("SELECT * FROM users WHERE id=?", (data["uid"],)).fetchone()
    if not u:
        raise HTTPException(401, "Unknown user")
    return u


def admin_user(u=Depends(current_user)):
    if not u["is_admin"]:
        raise HTTPException(403, "Admin only")
    return u


def settle(uid, kind, bet, payout):
    """Atomically check funds, apply result, log it. payout = total returned (0 on loss)."""
    if not (bet == bet) or bet <= 0 or bet > MAX_BET:
        raise HTTPException(400, f"Bet must be between 0 and {MAX_BET:g}")
    bet = round(bet, 2)
    with closing(db()) as c:
        c.execute("BEGIN IMMEDIATE")
        bal = c.execute("SELECT balance FROM users WHERE id=?", (uid,)).fetchone()["balance"]
        if bet > bal:
            c.execute("ROLLBACK")
            raise HTTPException(400, "Insufficient funds")
        payout = round(payout(bet) if callable(payout) else payout, 2)
        new = round(bal - bet + payout, 2)
        c.execute("UPDATE users SET balance=? WHERE id=?", (new, uid))
        c.execute("INSERT INTO transactions(user_id,kind,bet,payout,ts) VALUES(?,?,?,?,?)",
                  (uid, kind, bet, payout, time.time()))
        c.execute("COMMIT")
    return new


class Reg(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: str = ""
    password: str = Field(min_length=6, max_length=128)


@app.post("/register")
def register(r: Reg):
    name = r.username.strip().lower()
    with closing(db()) as c:
        try:
            c.execute("INSERT INTO users(username,email,pw,balance,is_admin) VALUES(?,?,?,?,?)",
                      (name, r.email, hash_pw(r.password), START_BALANCE, int(bool(ADMIN_USERNAME) and name == ADMIN_USERNAME)))
        except sqlite3.IntegrityError:
            raise HTTPException(400, "Username taken")
    return {"ok": True}


@app.post("/token")
def token(username: str = Form(), password: str = Form()):
    with closing(db()) as c:
        u = c.execute("SELECT * FROM users WHERE username=?", (username.strip().lower(),)).fetchone()
    if not u or not check_pw(password, u["pw"]):
        raise HTTPException(400, "Wrong username or password")
    return {"access_token": make_token(u["id"]), "token_type": "bearer"}


@app.get("/profile")
def profile(u=Depends(current_user)):
    return {"username": u["username"], "balance": u["balance"], "is_admin": bool(u["is_admin"])}


SLOTS = {"cherry": (2.0, 0.45, ["🍒", "🍋", "🔔"]), "diamond": (5.0, 0.18, ["💎", "7️⃣", "⭐"])}


@app.post("/slots/spin")
def spin(game_name: str = Form(), bet_amount: float = Form(), u=Depends(current_user)):
    if game_name not in SLOTS:
        raise HTTPException(400, "Unknown game")
    mult, p, syms = SLOTS[game_name]
    win = rng.random() < p
    if win:
        results = [syms[0]] * 3
    else:
        results = [rng.choice(syms) for _ in range(3)]
        while len(set(results)) == 1:
            results = [rng.choice(syms) for _ in range(3)]
    bal = settle(u["id"], game_name, bet_amount, (lambda b: b * mult) if win else 0)
    return {"results": results, "win_amount": round(bet_amount * mult, 2) if win else 0, "balance": bal}


RANKS = "23456789TJQKA"
HANDS = ["High card", "Pair", "Two pair", "Three of a kind", "Straight", "Flush", "Full house",
         "Four of a kind", "Straight flush"]


def score5(cards):
    r = sorted((RANKS.index(c[0]) for c in cards), reverse=True)
    cnt = Counter(r)
    groups = sorted(cnt.items(), key=lambda x: (x[1], x[0]), reverse=True)
    flush = len({c[1] for c in cards}) == 1
    uniq = sorted(set(r), reverse=True)
    straight = len(uniq) == 5 and uniq[0] - uniq[4] == 4
    if uniq == [12, 3, 2, 1, 0]:
        straight, r = True, [3, 2, 1, 0, -1]
    shape = [g[1] for g in groups]
    if straight and flush: cat = 8
    elif shape == [4, 1]: cat = 7
    elif shape == [3, 2]: cat = 6
    elif flush: cat = 5
    elif straight: cat = 4
    elif shape == [3, 1, 1]: cat = 3
    elif shape == [2, 2, 1]: cat = 2
    elif shape == [2, 1, 1, 1]: cat = 1
    else: cat = 0
    return (cat, [g[0] for g in groups] if not straight else r)


def best(cards7):
    return max(score5(list(c)) for c in itertools.combinations(cards7, 5))


class Poker(BaseModel):
    amount: float


@app.post("/poker")
def poker(p: Poker, u=Depends(current_user)):
    deck = [r + s for r in RANKS for s in "shdc"]
    rng.shuffle(deck)
    me, dealer, board = deck[:2], deck[2:4], deck[4:9]
    mine, theirs = best(me + board), best(dealer + board)
    if mine > theirs: status, mult = "Win", 2
    elif mine == theirs: status, mult = "Push", 1
    else: status, mult = "Lose", 0
    bal = settle(u["id"], "poker", p.amount, lambda b: b * mult)
    return {"cards": me, "dealer_cards": dealer, "board": board, "hand_name": HANDS[mine[0]],
            "status": status, "winnings": round(p.amount * (mult - 1), 2) if mult else 0, "balance": bal}


@app.get("/sports/events")
def events():
    with closing(db()) as c:
        return [dict(r) for r in c.execute("SELECT * FROM events")]


class SBet(BaseModel):
    event_id: int
    selection: str
    amount: float


@app.post("/sports/bet")
def sports_bet(b: SBet, u=Depends(current_user)):
    with closing(db()) as c:
        e = c.execute("SELECT * FROM events WHERE id=?", (b.event_id,)).fetchone()
    if not e or b.selection not in ("Home", "Away"):
        raise HTTPException(400, "Invalid event or selection")
    odds = e["odds_home"] if b.selection == "Home" else e["odds_away"]
    win = rng.random() < 0.93 / odds
    bal = settle(u["id"], "sports", b.amount, (lambda x: x * odds) if win else 0)
    return {"status": "Win" if win else "Lose", "winnings": round(b.amount * (odds - 1), 2) if win else 0, "balance": bal}


@app.get("/admin/dashboard")
def admin(u=Depends(admin_user)):
    with closing(db()) as c:
        users = [{"username": r["username"], "balance": r["balance"]} for r in c.execute("SELECT username,balance FROM users")]
        n = c.execute("SELECT COUNT(*) n FROM transactions").fetchone()["n"]
    return {"total_users": len(users), "total_transactions": n, "users": users}


@app.get("/")
def index():
    return FileResponse("index.html")
