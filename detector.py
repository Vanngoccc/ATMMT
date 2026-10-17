import re
import urllib.parse
from datetime import datetime

class SQLiDetector:
    """
    Lớp xử lý kiểm tra và phát hiện câu lệnh SQL Injection trong Request
    """
    def __init__(self):
        # Danh sách các luật (Rules) kiểm tra chuỗi truy vấn độc hại
        self.rules = [
            # Biểu thức kiểm tra dạng Boolean (Tautology: ' OR 1=1)
            (r"(?i)(\'|\")\s*(or|and)\s*(\'|\")?\s*\d+\s*=\s*\d+", "Lỗi Boolean SQLi (Tautology)", 90),
            (r"(?i)(\'|\")\s*(or|and)\s*(\'|\")?[a-z0-9]+\s*=\s*(\'|\")?[a-z0-9]+", "Lỗi Boolean SQLi (Tautology)", 85),
            (r"(?i)\b(or|and)\s+1\s*=\s*1\b", "Truy vấn luôn đúng (' OR 1=1)", 95),
            
            # Biểu thức kiểm tra dạng Union-based
            (r"(?i)\bunion\s+(all\s+)?select\b", "Khai thác dữ liệu bằng Union Select", 95),
            
            # Kiểm tra chèn câu lệnh can thiệp CSDL (; DROP, ; DELETE)
            (r"(?i);\s*(drop|alter|delete|truncate|update|insert)\b", "Tấn công thay đổi/xóa CSDL (DDL)", 100),
            
            # Kiểm tra dạng hoãn thời gian (Time-based Blind)
            (r"(?i)\b(sleep|benchmark|pg_sleep)\s*\(", "Tấn công hoãn thời gian (Time-based)", 90),
            (r"(?i)\bwaitfor\s+delay\b", "Tấn công hoãn thời gian (MSSQL)", 90),
            
            # Kiểm tra trích xuất thông tin cấu trúc CSDL
            (r"(?i)\b(information_schema|sys\.tables|sqlite_master|database\(\)|version\(\)|user\(\))\b", "Dò quét thông tin CSDL", 85),
            
            # Kiểm tra ký tự chú thích cắt câu lệnh SQL (-- , /* */)
            (r"(?i)(\'|\")\s*(;|--|#|/\*)", "Chèn ký tự chú thích cắt câu lệnh SQL", 75),
            (r"(?i)/\*\!.*?\*/", "Mã hóa câu lệnh MySQL Comment Bypass", 85),
        ]

    def analyze(self, text):
        """
        Hàm phân tích chuỗi đầu vào
        """
        if not text or not isinstance(text, str):
            return False, 0, "SAFE", []

        # Decode URL phòng trường hợp chuỗi bị mã hóa dạng %27 %20...
        decoded_text = text
        try:
            for _ in range(2):
                decoded_text = urllib.parse.unquote(decoded_text)
        except Exception:
            pass

        matched_list = []
        max_score = 0

        # Chạy qua từng luật regex để đối chiếu
        for pattern, rule_name, score in self.rules:
            if re.search(pattern, decoded_text):
                matched_list.append({
                    "rule": rule_name,
                    "pattern": pattern,
                    "score": score
                })
                if score > max_score:
                    max_score = score

        # Phân loại mức độ nguy hiểm
        if max_score >= 80:
            threat_level = "NGUY HIỂM CAO"
            is_sqli = True
        elif max_score >= 50:
            threat_level = "CẢNH BÁO"
            is_sqli = True
        elif max_score >= 30:
            threat_level = "NGHI VẤN"
            is_sqli = False
        else:
            threat_level = "AN TOÀN"
            is_sqli = False

        return is_sqli, max_score, threat_level, matched_list

    def check_request(self, params_dict, client_ip, endpoint):
        """
        Kiểm tra toàn bộ tham số gửi lên từ Client
        """
        detected_threats = []
        highest_score = 0
        should_block = False

        for field_name, value in params_dict.items():
            if isinstance(value, str):
                is_sqli, score, threat_level, matched = self.analyze(value)
                if is_sqli:
                    should_block = True
                if score > highest_score:
                    highest_score = score
                if matched:
                    detected_threats.append({
                        "field": field_name,
                        "value": value,
                        "score": score,
                        "threat_level": threat_level,
                        "matched_rules": matched
                    })

        log_data = None
        if detected_threats:
            log_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": client_ip,
                "endpoint": endpoint,
                "is_blocked": should_block,
                "highest_score": highest_score,
                "threats": detected_threats
            }

        return should_block, log_data

# Khởi tạo đối tượng detector
sqli_detector = SQLiDetector()
