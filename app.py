"""Quán Mì Xào Bò — Flask Backend"""
import hashlib
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, g, jsonify, render_template, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quan.db")
SALT = "quan-mixaobo-2024"

# ═══════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        import sqlite3
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS menu (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            name   TEXT NOT NULL,
            price  INTEGER NOT NULL,
            active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS orders (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_name TEXT NOT NULL,
            table_number  TEXT DEFAULT '',
            status        TEXT DEFAULT 'waiting',
            total_amount  INTEGER DEFAULT 0,
            created_at    TEXT DEFAULT (datetime('now','localtime')),
            updated_at    TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS order_items (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id     INTEGER NOT NULL,
            menu_item_id INTEGER NOT NULL,
            quantity     INTEGER DEFAULT 1,
            note         TEXT DEFAULT '',
            price        INTEGER NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id)
        );
    """)
    # Seed menu
    if db.execute("SELECT COUNT(*) FROM menu").fetchone()[0] == 0:
        menu = [
            ("🥩 Bò bít tết", 45000),
            ("🍜 Mì xào bò", 35000),
            ("🍝 Nui xào bò", 35000),
            ("🥟 Bánh mì xíu mại", 20000),
            ("🍲 Bánh mì bò kho", 25000),
            ("🥪 Bánh mì thịt", 15000),
            ("🍳 Bánh mì ốp la", 15000),
        ]
        db.executemany("INSERT INTO menu (name, price) VALUES (?, ?)", menu)
    db.commit()

# ═══════════════════════════════════════════
# AUTH HELPERS
# ═══════════════════════════════════════════

def hash_pin(pin: str) -> str:
    return hashlib.sha256(f"{SALT}:{pin}".encode()).hexdigest()

def get_config(key: str) -> str | None:
    row = get_db().execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None

def set_config(key: str, value: str):
    get_db().execute(
        "INSERT INTO config (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=?",
        (key, value, value),
    )
    get_db().commit()

def require_bep(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get("bep_authed"):
            return jsonify(error="Chưa xác thực BẾP"), 401
        return f(*a, **kw)
    return wrap

def require_admin(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get("admin_authed"):
            return jsonify(error="Chưa xác thực ADMIN"), 401
        return f(*a, **kw)
    return wrap

# ═══════════════════════════════════════════
# ROUTES — PAGES
# ═══════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")

# ═══════════════════════════════════════════
# ROUTES — SETUP
# ═══════════════════════════════════════════

@app.route("/api/setup/status")
def setup_status():
    """Check if setup has been done."""
    bh = get_config("bep_pin_hash")
    ah = get_config("admin_pin_hash")
    return jsonify(needs_setup=not (bh and ah))

@app.route("/api/setup", methods=["POST"])
def do_setup():
    data = request.get_json() or {}
    bep = (data.get("bep_pin") or "").strip()
    admin = (data.get("admin_pin") or "").strip()

    if get_config("bep_pin_hash") or get_config("admin_pin_hash"):
        return jsonify(error="Đã thiết lập rồi"), 400
    if not bep.isdigit() or len(bep) != 4:
        return jsonify(error="Mã BẾP phải đúng 4 chữ số"), 400
    if not admin.isdigit() or len(admin) != 6:
        return jsonify(error="Mã ADMIN phải đúng 6 chữ số"), 400
    if bep == admin:
        return jsonify(error="Mã BẾP và ADMIN không được giống nhau"), 400

    set_config("bep_pin_hash", hash_pin(bep))
    set_config("admin_pin_hash", hash_pin(admin))
    return jsonify(ok=True)

# ═══════════════════════════════════════════
# ROUTES — AUTH
# ═══════════════════════════════════════════

@app.route("/api/auth/bep", methods=["POST"])
def auth_bep():
    pin = (request.get_json() or {}).get("pin", "")
    correct = get_config("bep_pin_hash")
    if not correct:
        return jsonify(error="Chưa thiết lập"),400
    if hash_pin(pin) == correct:
        session["bep_authed"] = True
        return jsonify(ok=True)
    return jsonify(error="Sai mã PIN"), 401

@app.route("/api/auth/admin", methods=["POST"])
def auth_admin():
    pin = (request.get_json() or {}).get("pin", "")
    correct = get_config("admin_pin_hash")
    if not correct:
        return jsonify(error="Chưa thiết lập"),400
    if hash_pin(pin) == correct:
        session["admin_authed"] = True
        return jsonify(ok=True)
    return jsonify(error="Sai mã PIN"), 401

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify(ok=True)

@app.route("/api/auth/me")
def auth_me():
    return jsonify(
        bep=bool(session.get("bep_authed")),
        admin=bool(session.get("admin_authed")),
    )

# ═══════════════════════════════════════════
# ROUTES — MENU
# ═══════════════════════════════════════════

@app.route("/api/menu")
def get_menu():
    rows = get_db().execute(
        "SELECT id, name, price FROM menu WHERE active=1 ORDER BY id"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

# ═══════════════════════════════════════════
# ROUTES — ORDERS
# ═══════════════════════════════════════════

@app.route("/api/orders", methods=["POST"])
def create_order():
    data = request.get_json() or {}
    name = (data.get("customer_name") or "").strip()
    tbl  = (data.get("table_number") or "").strip()
    items = data.get("items") or []

    if not name:
        return jsonify(error="Vui lòng nhập tên"), 400
    if not items:
        return jsonify(error="Chọn ít nhất 1 món"), 400

    db = get_db()
    total = 0
    cur = db.execute(
        "INSERT INTO orders (customer_name, table_number, total_amount) VALUES (?,?,0)",
        (name, tbl),
    )
    order_id = cur.lastrowid
    for it in items:
        mid = it["menu_item_id"]
        qty = max(1, int(it.get("quantity", 1)))
        note = (it.get("note") or "").strip()
        price_row = db.execute("SELECT price FROM menu WHERE id=?", (mid,)).fetchone()
        price = price_row["price"] if price_row else 0
        total += price * qty
        db.execute(
            "INSERT INTO order_items (order_id, menu_item_id, quantity, note, price) VALUES (?,?,?,?,?)",
            (order_id, mid, qty, note, price),
        )
    db.execute("UPDATE orders SET total_amount=? WHERE id=?", (total, order_id))
    db.commit()
    return jsonify(ok=True, order_id=order_id)

@app.route("/api/orders")
def list_orders():
    status = request.args.get("status", "")
    db = get_db()
    if status:
        rows = db.execute(
            "SELECT * FROM orders WHERE status=? ORDER BY created_at ASC", (status,)
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()

    orders = []
    for r in rows:
        o = dict(r)
        items = db.execute(
            "SELECT oi.*, m.name as menu_name FROM order_items oi JOIN menu m ON oi.menu_item_id=m.id WHERE oi.order_id=?",
            (o["id"],),
        ).fetchall()
        o["items"] = [dict(i) for i in items]
        orders.append(o)
    return jsonify(orders)

@app.route("/api/orders/<int:oid>")
def get_order(oid):
    o = get_db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not o:
        return jsonify(error="Không tìm thấy đơn"), 404
    order = dict(o)
    items = get_db().execute(
        "SELECT oi.*, m.name as menu_name FROM order_items oi JOIN menu m ON oi.menu_item_id=m.id WHERE oi.order_id=?",
        (oid,),
    ).fetchall()
    order["items"] = [dict(i) for i in items]
    return jsonify(order)

@app.route("/api/orders/<int:oid>/status", methods=["PUT"])
def update_order_status(oid):
    data = request.get_json() or {}
    new_status = data.get("status", "")
    if new_status not in ("waiting", "done", "paid", "cancelled"):
        return jsonify(error="Trạng thái không hợp lệ"), 400

    db = get_db()
    db.execute(
        "UPDATE orders SET status=?, updated_at=datetime('now','localtime') WHERE id=?",
        (new_status, oid),
    )
    db.commit()
    return jsonify(ok=True)

# ═══════════════════════════════════════════
# ROUTES — STATS
# ═══════════════════════════════════════════

@app.route("/api/stats/today")
@require_admin
def stats_today():
    today = datetime.now().strftime("%Y-%m-%d")
    db = get_db()

    total_orders = db.execute(
        "SELECT COUNT(*) as c FROM orders WHERE date(created_at)=?", (today,)
    ).fetchone()["c"]

    done_orders = db.execute(
        "SELECT COUNT(*) as c FROM orders WHERE date(created_at)=? AND status='done'",
        (today,),
    ).fetchone()["c"]

    paid_revenue = db.execute(
        "SELECT COALESCE(SUM(total_amount),0) as t FROM orders WHERE date(created_at)=? AND status='paid'",
        (today,),
    ).fetchone()["t"]

    total_items = db.execute("""
        SELECT COALESCE(SUM(oi.quantity),0) as t
        FROM order_items oi JOIN orders o ON oi.order_id=o.id
        WHERE date(o.created_at)=? AND o.status IN ('done','paid')
    """, (today,)).fetchone()["t"]

    # Top items
    top = db.execute("""
        SELECT m.name, SUM(oi.quantity) as qty
        FROM order_items oi
        JOIN orders o ON oi.order_id=o.id
        JOIN menu m ON oi.menu_item_id=m.id
        WHERE date(o.created_at)=? AND o.status IN ('done','paid')
        GROUP BY m.name ORDER BY qty DESC
    """, (today,)).fetchall()

    return jsonify(
        total_orders=total_orders,
        done_orders=done_orders,
        paid_revenue=paid_revenue,
        total_items=total_items,
        avg_per_order=round(paid_revenue / done_orders) if done_orders else 0,
        top_items=[dict(r) for r in top],
        date=today,
    )

@app.route("/api/stats/weekly")
@require_admin
def stats_weekly():
    db = get_db()
    days = []
    for d in range(6, -1, -1):
        date = (datetime.now() - timedelta(days=d)).strftime("%Y-%m-%d")
        row = db.execute(
            "SELECT COUNT(*) as c, COALESCE(SUM(total_amount),0) as t FROM orders WHERE date(created_at)=? AND status IN ('done','paid')",
            (date,),
        ).fetchone()
        days.append({"date": date, "orders": row["c"], "revenue": row["t"]})
    return jsonify(days)

@app.route("/api/stats/pending_payments")
@require_admin
def pending_payments():
    """Orders done but not yet paid."""
    db = get_db()
    rows = db.execute(
        "SELECT id, customer_name, table_number, total_amount, created_at FROM orders WHERE status='done' ORDER BY created_at ASC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

# ═══════════════════════════════════════════
# ROUTES — DATA MANAGEMENT
# ═══════════════════════════════════════════

@app.route("/api/reset/today", methods=["POST"])
@require_admin
def reset_today():
    today = datetime.now().strftime("%Y-%m-%d")
    db = get_db()
    db.execute("""
        DELETE FROM order_items WHERE order_id IN (
            SELECT id FROM orders WHERE date(created_at)=?
        )
    """, (today,))
    db.execute("DELETE FROM orders WHERE date(created_at)=?", (today,))
    db.commit()
    return jsonify(ok=True)

# ═══════════════════════════════════════════
# ROUTES — PIN MANAGEMENT
# ═══════════════════════════════════════════

@app.route("/api/config/pin/bep", methods=["PUT"])
@require_admin
def change_bep_pin():
    pin = (request.get_json() or {}).get("pin", "").strip()
    if not pin.isdigit() or len(pin) != 4:
        return jsonify(error="Mã BẾP phải đúng 4 chữ số"), 400
    set_config("bep_pin_hash", hash_pin(pin))
    return jsonify(ok=True)

@app.route("/api/config/pin/admin", methods=["PUT"])
@require_admin
def change_admin_pin():
    pin = (request.get_json() or {}).get("pin", "").strip()
    if not pin.isdigit() or len(pin) != 6:
        return jsonify(error="Mã ADMIN phải đúng 6 chữ số"), 400
    set_config("admin_pin_hash", hash_pin(pin))
    return jsonify(ok=True)

# ═══════════════════════════════════════════
# HOOK — init DB on first request
# ═══════════════════════════════════════════

@app.before_request
def _init():
    init_db()

# ═══════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
