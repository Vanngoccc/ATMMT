import sqlite3
import json
import sys
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from detector import sqli_detector

app = Flask(__name__)
app.secret_key = "do_an_atmmt_sqli_2026"
DB_PATH = "database.db"

# Hàm khởi tạo database SQLite
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Bảng tài khoản người dùng
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            fullname TEXT,
            role TEXT
        )
    ''')
    
    # Bảng sản phẩm
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            category TEXT,
            price REAL
        )
    ''')

    # Bảng lưu nhật ký tấn công
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            endpoint TEXT,
            payload TEXT,
            risk_score INTEGER,
            threat_level TEXT,
            rule_matched TEXT,
            action_taken TEXT
        )
    ''')

    # Thêm dữ liệu mẫu thử nghiệm
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, fullname, role) VALUES ('admin', 'admin123', 'Quản trị viên', 'admin')")
        cursor.execute("INSERT INTO users (username, password, fullname, role) VALUES ('sv_nam', '123456', 'Nguyễn Văn Nam', 'user')")
        cursor.execute("INSERT INTO users (username, password, fullname, role) VALUES ('sv_hoa', 'hoa2026', 'Trần Thị Hoa', 'user')")

    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO products (name, category, price) VALUES ('Laptop Dell Inspiron', 'Máy tính', 16500000)")
        cursor.execute("INSERT INTO products (name, category, price) VALUES ('Điện thoại Samsung Galaxy', 'Điện thoại', 12000000)")
        cursor.execute("INSERT INTO products (name, category, price) VALUES ('Tai nghe Bluetooth', 'Phụ kiện', 850000)")
        cursor.execute("INSERT INTO products (name, category, price) VALUES ('Bàn phím cơ Logitech', 'Phụ kiện', 1450000)")
        cursor.execute("INSERT INTO products (name, category, price) VALUES ('Màn hình ASUS 24 inch', 'Máy tính', 3800000)")

    conn.commit()
    conn.close()

# Hàm lưu lịch sử cảnh báo SQLi vào DB
def save_log(log_data):
    if not log_data:
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for threat in log_data['threats']:
        payload_text = f"{threat['field']}: {threat['value']}"
        rules_text = ", ".join([r['rule'] for r in threat['matched_rules']])
        action = "Chặn HTTP 403" if log_data['is_blocked'] else "Cảnh báo"
        
        cursor.execute('''
            INSERT INTO attack_logs (timestamp, client_ip, endpoint, payload, risk_score, threat_level, rule_matched, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_data['timestamp'],
            log_data['client_ip'],
            log_data['endpoint'],
            payload_text,
            threat['score'],
            threat['threat_level'],
            rules_text,
            action
        ))
    conn.commit()
    conn.close()

# Truyền biến chế độ bảo vệ vào template HTML
@app.context_processor
def inject_status():
    security_mode = session.get('security_mode', 'PROTECTED')
    return dict(security_mode=security_mode)

# Nút đổi chế độ Bật/Tắt bảo vệ để demo
@app.route('/toggle_mode', methods=['POST'])
def toggle_mode():
    current = session.get('security_mode', 'PROTECTED')
    session['security_mode'] = 'VULNERABLE' if current == 'PROTECTED' else 'PROTECTED'
    mode = session['security_mode']
    status_str = "BẬT BẢO VỆ (Protected)" if mode == 'PROTECTED' else "TẮT BẢO VỆ (Vulnerable)"
    flash(f"Đã chuyển chế độ hệ thống: {status_str}", "info")
    return redirect(request.referrer or url_for('index'))

@app.route('/')
def index():
    query = request.args.get('q', '').strip()
    security_mode = session.get('security_mode', 'PROTECTED')
    
    # Nếu đang BẬT BẢO VỆ -> Kiểm tra câu truy vấn q
    if security_mode == 'PROTECTED' and query:
        should_block, log_data = sqli_detector.check_request({'q': query}, request.remote_addr, request.path)
        if should_block:
            save_log(log_data)
            return render_template('blocked.html', log=log_data, payload=query), 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    products = []
    sql_executed = ""
    sql_error = ""
    
    if query:
        if security_mode == 'VULNERABLE':
            # Chế độ dính lỗi SQLi: Nối chuỗi trực tiếp
            sql_executed = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR category LIKE '%{query}%'"
            try:
                cursor.execute(sql_executed)
                products = cursor.fetchall()
            except Exception as e:
                sql_error = str(e)
        else:
            # Chế độ an toàn: Dùng Parameterized Query
            sql_executed = "SELECT * FROM products WHERE name LIKE ? OR category LIKE ?"
            param = f"%{query}%"
            cursor.execute(sql_executed, (param, param))
            products = cursor.fetchall()
    else:
        sql_executed = "SELECT * FROM products"
        cursor.execute(sql_executed)
        products = cursor.fetchall()
        
    conn.close()
    return render_template('index.html', products=products, query=query, sql_executed=sql_executed, sql_error=sql_error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    security_mode = session.get('security_mode', 'PROTECTED')
    
    # Kiểm tra nhận diện SQLi ở form Đăng nhập
    if security_mode == 'PROTECTED':
        should_block, log_data = sqli_detector.check_request({'username': username, 'password': password}, request.remote_addr, request.path)
        if should_block:
            save_log(log_data)
            return render_template('blocked.html', log=log_data, payload=f"User: {username} | Pass: {password}"), 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    user = None
    sql_executed = ""
    sql_error = ""

    if security_mode == 'VULNERABLE':
        # Nối chuỗi bị lỗi SQLi Bypass
        sql_executed = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            cursor.execute(sql_executed)
            user = cursor.fetchone()
        except Exception as e:
            sql_error = str(e)
    else:
        # Sử dụng tham số an toàn
        sql_executed = "SELECT * FROM users WHERE username = ? AND password = ?"
        cursor.execute(sql_executed, (username, password))
        user = cursor.fetchone()

    conn.close()

    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['fullname'] = user[3]
        session['role'] = user[4]
        flash(f"Đăng nhập thành công! Xin chào {user[3]}", "success")
        return redirect(url_for('index'))
    else:
        flash("Tài khoản hoặc mật khẩu không chính xác!", "danger")
        return render_template('login.html', username=username, sql_executed=sql_executed, sql_error=sql_error)

@app.route('/logout')
def logout():
    session.clear()
    flash("Đã đăng xuất tài khoản.", "info")
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM attack_logs ORDER BY id DESC LIMIT 50")
    logs = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM attack_logs")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE threat_level LIKE '%NGUY HIỂM%'")
    critical_count = cursor.fetchone()[0]

    conn.close()
    return render_template('admin.html', logs=logs, total=total, critical_count=critical_count)

if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    init_db()
    print("-" * 50)
    print("CHUONG TRINH DEMO DO AN AN TOAN MANG MAY TINH")
    print("Website running at: http://127.0.0.1:5000")
    print("Admin Dashboard at: http://127.0.0.1:5000/admin")
    print("-" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)
