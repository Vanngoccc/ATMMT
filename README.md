# ĐỒ ÁN AN TOÀN MẠNG MÁY TÍNH - ĐỀ TÀI 9
## HỆ THỐNG PHÁT HIỆN SQL INJECTION (SQL INJECTION DETECTION)

Trường Đại học Công Thương TP. Hồ Chí Minh (HUIT)  
Khoa Công nghệ Thông tin  

---

### 1. Giới thiệu
Đồ án xây dựng một trang web nhỏ bằng Python Flask và CSDL SQLite để mô phỏng và phát hiện tấn công SQL Injection.

### 2. Các file chính trong thư mục
- `app.py`: File chạy chương trình web Flask.
- `detector.py`: File chứa class kiểm tra và phát hiện SQLi.
- `database.db`: CSDL SQLite (tự tạo khi chạy app).
- `templates/`: Thư mục chứa các giao diện HTML.
- `Bao_Cao_Do_An_SQL_Injection_Detection.md`: File nội dung báo cáo đồ án.

### 3. Cách chạy ứng dụng
1. Mở Command Prompt hoặc Terminal tại thư mục `D:\ATMMT\De_Tai_9_SQL_Injection_Detection`.
2. Chạy lệnh:
   ```bash
   python app.py
   ```
3. Truy cập vào trình duyệt:
   - Trang chủ: `http://127.0.0.1:5000`
   - Trang đăng nhập: `http://127.0.0.1:5000/login`
   - Trang Admin: `http://127.0.0.1:5000/admin`

### 4. Hướng dẫn thử nghiệm demo
- Trên thanh menu có nút bấm chuyển trạng thái **Protected** và **Vulnerable**.
- Khi ở chế độ **TẮT BẢO VỆ (Vulnerable)**: Vào trang Đăng nhập nhập username: `admin' --` và pass bất kỳ -> Đăng nhập thành công.
- Khi ở chế độ **BẬT BẢO VỆ (Protected)**: Thực hiện lại thao tác trên -> Hệ thống chặn và trả về trang HTTP 403.
- Truy cập `/admin` để xem danh sách lịch sử các cuộc tấn công bị ghi nhận.
