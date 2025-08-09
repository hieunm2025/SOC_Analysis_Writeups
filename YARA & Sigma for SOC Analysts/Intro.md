### Giới thiệu về YARA và Sigma

**YARA:** Phân tích tệp và bộ nhớ
**Sigma:** Phân tích nhật ký SIEM

### Tầm quan trọng của YARA và Sigma

* **Phát hiện mối đe dọa hiệu quả:** Các quy tắc YARA và Sigma giúp các nhà phân tích SOC tạo ra các quy tắc phát hiện tùy chỉnh cho môi trường và nhu cầu bảo mật riêng, từ đó phát hiện và giải quyết các sự cố tiềm ẩn.

  * Ví dụ các repo quy tắc YARA và Sigma:

    * YARA: [Yara Rules](https://github.com/Yara-Rules/rules/tree/master/malware), [Open Source YARA](https://github.com/mikesxrs/Open-Source-YARA-rules/tree/master)
    * Sigma: [SigmaHQ](https://github.com/SigmaHQ/sigma/tree/master/rules), [joesecurity](https://github.com/joesecurity/sigma-rules), [mdecrevoisier](https://github.com/mdecrevoisier/SIGMA-detection-rules)

* **Phân tích nhật ký hiệu quả:** Quy tắc Sigma rất hữu ích trong việc phân tích nhật ký trong môi trường SOC, giúp phân loại và tương quan dữ liệu từ nhiều nguồn khác nhau.

* **Hợp tác và Chuẩn hóa:** Các báo cáo DFIR và quy tắc của cộng đồng giúp cải thiện khả năng chia sẻ thông tin và chuẩn hóa phát hiện mối đe dọa.

  * DFIR Report: [Yara Rules](https://github.com/The-DFIR-Report/Yara-Rules), [Sigma Rules](https://github.com/The-DFIR-Report/Sigma-Rules)

* **Tích hợp với các công cụ bảo mật:** YARA và Sigma dễ dàng tích hợp với các công cụ bảo mật hiện có để tối ưu hóa phát hiện mối đe dọa.

* **Phát hiện và phân loại malware:** Quy tắc YARA giúp các nhà phân tích xác định và phân loại malware qua các mẫu hoặc đặc điểm nhận diện cụ thể.

* **Xác định chỉ số xâm nhập (IOC):** Cả YARA và Sigma đều giúp xác định các IOC, là các dấu hiệu hoặc hành vi liên quan đến sự cố bảo mật, giúp phát hiện sớm và khắc phục kịp thời.
