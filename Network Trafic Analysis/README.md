
# 🧠 Tổng Quan về Network Traffic Analysis (NTA)

**Network Traffic Analysis (NTA)** là quá trình kiểm tra lưu lượng mạng nhằm:
- Hiểu rõ hoạt động mạng
- Phát hiện bất thường
- Ứng phó với mối đe dọa

Một công cụ thiết yếu để:
- Tăng khả năng hiển thị mạng
- Phát hiện sớm các mối đe dọa
- Tuân thủ quy định bảo mật

---

## 🎯 Mục Tiêu & Trường Hợp Sử Dụng

- **Phát hiện mối đe dọa**:
  - Phân tích lưu lượng thời gian thực (ransomware, khai thác, v.v.)
  - Nhận diện lưu lượng bất thường (cổng không chuẩn, máy chủ đáng ngờ)
  - Phát hiện mã độc trên đường truyền

- **Thiết lập đường cơ sở (Baseline)**:
  - Xây dựng hồ sơ lưu lượng mạng "bình thường"

- **Điều tra sự cố & Săn tìm mối đe dọa**:
  - Phân tích sự cố đã xảy ra
  - Chủ động tìm kiếm mối đe dọa tiềm ẩn

---

## 🧠 Kỹ Năng & Kiến Thức Cần Thiết

- Hiểu mô hình **TCP/IP** & **OSI**
- Kiến thức cơ bản về **Switching**, **Routing**
- Hiểu các **cổng & giao thức phổ biến**
- Phân biệt gói **TCP** vs **UDP**
- Khả năng đọc dữ liệu **Encapsulation**

---

## 🛠️ Công Cụ Phân Tích Lưu Lượng Phổ Biến

| Công Cụ      | Mô Tả |
|--------------|--------|
| **tcpdump**  | Dòng lệnh, bắt và phân tích lưu lượng mạng |
| **Tshark**   | Dòng lệnh của Wireshark |
| **Wireshark**| Giao diện đồ họa, phân tích sâu giao thức |
| **NGrep**    | Khớp mẫu regex/BPF với dữ liệu mạng |
| **Span Port**| Sao chép lưu lượng đến thiết bị phân tích |
| **Network Tap** | Thiết bị phần cứng tách lưu lượng |
| **tcpick**   | Theo dõi phiên TCP |
| **Elastic Stack** | Phân tích và trực quan hóa dữ liệu log |
| **SIEM (Splunk)** | Phân tích và cảnh báo dữ liệu tập trung |

---

## 🔍 Cú Pháp BPF (Berkeley Packet Filter)

- **Mục đích**: Lọc lưu lượng ở lớp Data-Link
- **Ứng dụng**: tcpdump, Wireshark, Tshark, NGrep
- **Ví dụ**:  
  ```bash
  host 192.168.1.1 and port 80
  ```

---

## ⚙️ Quy Trình NTA (Workflow)

1. **Tiếp nhận lưu lượng**
   - Đặt điểm giám sát (tap/span port)
   - Thu thập có lọc mục tiêu (nếu có)

2. **Giảm nhiễu bằng lọc**
   - Loại bỏ broadcast, multicast không cần thiết

3. **Phân tích & khám phá**
   - Truy vết địa chỉ, giao thức, cờ TCP
   - Câu hỏi gợi ý:
     - Có mã hóa bất thường không?
     - Có truy cập trái phép không?

4. **Phát hiện & cảnh báo**
   - Dùng IDS/IPS, heuristic, signature
   - Đánh giá: Lưu lượng lành tính hay độc hại?

5. **Khắc phục & giám sát**
   - Sau khi xử lý sự cố, tiếp tục theo dõi
   - Duy trì dashboard tập trung để giám sát liên tục

---

## 📚 Ghi chú

- NTA là một **quy trình động**, không phải vòng lặp cố định
- Tính hiệu quả phụ thuộc vào **mục tiêu phân tích** và **khả năng hiển thị mạng**
