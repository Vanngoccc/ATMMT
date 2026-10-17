TRƯỜNG ĐẠI HỌC CÔNG THƯƠNG TP. HỒ CHÍ MINH
KHOA CÔNG NGHỆ THÔNG TIN
BỘ MÔN AN TOÀN MẠNG MÁY TÍNH

--------------------------------------------------
BÁO CÁO ĐỒ ÁN MÔN HỌC
ĐỀ TÀI: TÌM HIỂU VÀ TRIỂN KHAI HỆ THỐNG PHÁT HIỆN SQL INJECTION
--------------------------------------------------

Giảng viên hướng dẫn: [Tên Giảng Viên]
Sinh viên thực hiện:  [Tên Sinh Viên / Nhóm Sinh Viên]
Mã số sinh viên:     [MSSV]
Lớp:                 [Tên Lớp]

TP. Hồ Chí Minh, Năm 2026


==================================================
MỤC LỤC
==================================================
LỜI MỞ ĐẦU
CHƯƠNG 1: TỔNG QUAN ĐỀ TÀI
  1.1. Lý do chọn đề tài
  1.2. Mục tiêu của đồ án
  1.3. Phạm vi thực hiện
CHƯƠNG 2: CƠ SỞ LÝ THUYẾT VỀ LỖ HỔNG SQL INJECTION
  2.1. Khái niệm về SQL Injection
  2.2. Nguyên nhân gây ra lỗi
  2.3. Các dạng tấn công SQL Injection phổ biến
CHƯƠNG 3: THIẾT KẾ VÀ XÂY DỰNG HỆ THỐNG PHÁT HIỆN
  3.1. Mô hình tổng quan của ứng dụng
  3.2. Thuật toán nhận diện dựa trên luật (Rule-based)
  3.3. Đánh giá điểm rủi ro (Risk Score)
CHƯƠNG 4: THỰC NGHIỆM VÀ KẾT QUẢ DEMO
  4.1. Môi trường cài đặt
  4.2. Kịch bản thử nghiệm 1: Bypass Đăng nhập khi tắt bảo vệ
  4.3. Kịch bản thử nghiệm 2: Chặn truy vấn độc hại khi bật bảo vệ
  4.4. Quản lý nhật ký tấn công trên Admin Dashboard
CHƯƠNG 5: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN
  5.1. Kết quả đạt được
  5.2. Hạn chế và hướng cải tiến
TÀI LIỆU THAM KHẢO


==================================================
LỜI MỞ ĐẦU
==================================================
Hiện nay, sự phát triển nhanh chóng của các ứng dụng web kéo theo nhiều nguy cơ về an toàn thông tin. Trong đó, SQL Injection là một trong những lỗ hổng kinh điển và nguy hiểm nhất đối với các hệ thống có sử dụng cơ sở dữ liệu.

Trong khuôn khổ môn học An toàn mạng máy tính tại Trường Đại học Công Thương TP.HCM, nhóm chúng em chọn đề tài "Tìm hiểu và triển khai hệ thống phát hiện SQL Injection" nhằm mục đích nắm vững cơ chế hoạt động của lỗ hổng này, đồng thời xây dựng một mô hình thử nghiệm có khả năng nhận diện và ngăn chặn các truy vấn bất thường.


==================================================
CHƯƠNG 1: TỔNG QUAN ĐỀ TÀI
==================================================
1.1. Lý do chọn đề tài:
SQL Injection (SQLi) cho phép kẻ tấn công chèn các câu lệnh SQL không hợp lệ vào tham số đầu vào. Nếu ứng dụng không xử lý kỹ, hacker có thể lấy toàn bộ dữ liệu trong CSDL, thay đổi dữ liệu hoặc bypass qua màn hình đăng nhập. Đề tài giúp sinh viên hiểu rõ cả hai khía cạnh: cách lỗ hổng bị khai thác và cách viết mã an toàn để phòng tránh.

1.2. Mục tiêu của đồ án:
- Tìm hiểu lý thuyết về lỗ hổng SQL Injection và các kỹ thuật khai thác cơ bản.
- Xây dựng một trang web thương mại điện tử nhỏ bằng Python (Flask + SQLite) làm môi trường thử nghiệm.
- Viết bộ lọc phát hiện (SQLi Detector Engine) kiểm tra các request đầu vào.
- Thiết kế giao diện cho phép chuyển đổi qua lại giữa chế độ cho phép dính lỗi (để demo tấn công) và chế độ bật bảo vệ (để demo ngăn chặn).

1.3. Phạm vi thực hiện:
- Ứng dụng chạy thử nghiệm trên môi trường Localhost (Windows).
- Tập trung vào các kỹ thuật SQLi phổ biến: Boolean-based (' OR 1=1), Union-based, DDL Injection (DROP TABLE), Time-based.


==================================================
CHƯƠNG 2: CƠ SỞ LÝ THUYẾT VỀ LỖ HỔNG SQL INJECTION
==================================================
2.1. Khái niệm:
SQL Injection xảy ra khi dữ liệu nhập vào của người dùng bị nối trực tiếp vào chuỗi câu lệnh SQL gửi đến máy chủ CSDL mà không qua bước kiểm tra hay chuẩn hóa.

2.2. Ví dụ nguyên nhân dính lỗi:
Giả sử đoạn code xử lý đăng nhập nối chuỗi như sau:
sql = "SELECT * FROM users WHERE username = '" + user_input + "' AND password = '" + pass_input + "'"

Khi người dùng nhập username là: admin' --
Câu lệnh thực thi thực tế sẽ thành:
SELECT * FROM users WHERE username = 'admin' --' AND password = '...'

Ký tự '--' khiến toàn bộ đoạn kiểm tra mật khẩu đằng sau bị bỏ qua, dẫn đến việc đăng nhập thành công mà không cần đúng mật khẩu.

2.3. Các dạng SQL Injection:
- Boolean-based SQLi: Sử dụng các mệnh đề luôn đúng như ' OR '1'='1 để làm sai lệch logic truy vấn.
- Union-based SQLi: Sử dụng từ khóa UNION SELECT để ghép nối dữ liệu từ các bảng khác (ví dụ trích xuất username/password).
- Time-based Blind SQLi: Chèn các hàm hoãn thời gian như SLEEP() để dò đoán thông tin.


==================================================
CHƯƠNG 3: THIẾT KẾ VÀ XÂY DỰNG HỆ THỐNG PHÁT HIỆN
==================================================
3.1. Mô hình tổng quan:
Hệ thống gồm 3 thành phần chính:
- User Interface: Các trang HTML giao diện (index, login, admin, blocked).
- Security Middleware (detector.py): Bộ kiểm tra đầu vào trước khi dữ liệu đi vào CSDL.
- Database (database.db): CSDL SQLite chứa bảng users, products và attack_logs.

3.2. Thuật toán nhận diện dựa trên luật (Rule-based):
Bộ lọc detector.py chứa tập hợp các biểu thức chính quy (Regex) đại diện cho các mẫu tấn công SQLi phổ biến. Khi có dữ liệu gửi lên, hệ thống sẽ URL-decode chuỗi đầu vào và chạy kiểm tra qua từng luật.

3.3. Đánh giá điểm rủi ro (Risk Score):
Mỗi luật vi phạm sẽ có một số điểm tương ứng (từ 70 đến 100 điểm).
- Nếu Risk Score >= 80: Đánh giá mức NGUY HIỂM CAO -> Hệ thống tự động chặn (Trả về HTTP 403) và ghi log.
- Nếu Risk Score < 50: Cho phép truy cập bình thường.


==================================================
CHƯƠNG 4: THỰC NGHIỆM VÀ KẾT QUẢ DEMO
==================================================
4.1. Môi trường cài đặt:
- Hệ điều hành: Windows 10/11.
- Ngôn ngữ lập trình: Python 3.11.
- Thư viện sử dụng: Flask, sqlite3, re, urllib.

4.2. Kịch bản 1 - Tắt bảo vệ (Vulnerable Mode):
- Chuyển hệ thống sang chế độ "TẮT BẢO VỆ".
- Vào trang Đăng nhập, nhập username: admin' -- và pass bất kỳ.
- Kết quả: Đăng nhập thành công vào tài khoản Admin.

4.3. Kịch bản 2 - Bật bảo vệ (Protected Mode):
- Chuyển hệ thống sang chế độ "BẬT BẢO VỆ".
- Nhập lại thông tin tấn công admin' --.
- Kết quả: Hệ thống chuyển sang trang "HTTP 403 - CẢNH BÁO AN NINH" và ngăn chặn truy cập.

4.4. Quản lý nhật ký trên Admin Dashboard:
Vào địa chỉ http://127.0.0.1:5000/admin để xem danh sách lịch sử các lần tấn công bị chặn kèm theo IP, thời gian, payload và luật vi phạm.


==================================================
CHƯƠNG 5: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN
==================================================
5.1. Kết quả đạt được:
- Đồ án đã hoàn thành việc nghiên cứu lý thuyết về SQL Injection.
- Xây dựng thành công ứng dụng demo trực quan, dễ thao tác thử nghiệm.
- Viết được bộ lọc phát hiện theo luật cơ bản hoạt động ổn định.

5.2. Hạn chế và hướng phát triển:
- Bộ lọc hiện tại dựa trên các biểu thức Regex cố định, có thể bị qua mặt nếu attacker dùng kỹ thuật obfuscation quá phức tạp.
- Hướng phát triển: Ứng dụng thêm mô hình Học máy (Machine Learning) để phân loại chuỗi truy vấn thông minh hơn.


==================================================
TÀI LIỆU THAM KHẢO
==================================================
1. Tài liệu môn học An toàn mạng máy tính - Trường ĐH Công Thương TP.HCM.
2. OWASP Top 10 Web Application Security Risks.
3. Tài liệu hướng dẫn lập trình Python Flask & SQLite documentation.
