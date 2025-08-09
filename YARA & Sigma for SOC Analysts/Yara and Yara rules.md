Yara và cách hoạt động của nó

Yara là một tool mạnh mẽ để nhận diện và phân loại file dựa trên các mẫu, đặc điểm hoặc nội dung cụ thể. Các nhà phân tích SOC thường sử dụng các quy tắc YARA để phát hiện và phân loại phần mềm độc hại, tệp đáng ngờ và chỉ số xâm nhập (IOC). Yara giúp nhận diện các mẫu cả văn bản và nhị phân, có thể áp dụng trong hoạt động điều tra bộ nhớ.

Khi áp dụng, YARA quét các tệp hoặc thư mục và so sánh chúng với các quy tắc đã định nghĩa. Nếu một tệp khớp với các mẫu hoặc điều kiện cụ thể, nó có thể kích hoạt alert hoặc yêu cầu kiểm tra thêm như một mối đe dọa bảo mật tiềm ẩn

Ứng dụng của YARA
1. Phát hiện và phân loại malware: YARA rất hữu ích trong việc phát hiện và phân loại phần mềm độc hại dựa trên các mẫu đặc trưng, hành vi hoặc thuộc tính của tệp
2. Phân tích và phân loại tệp: YARA có thể phân tích và phân loại tệp dựa trên đặc điểm như định dạng tệp, phiên bản, metada, các công cụ đóng gói, và các đặc điểm khác
3. Phát hiện chỉ số xâm nhập(IOC): YARA có thể tìm kiếm các IOC đặc thù trong các tệp hoặc thư mục, giúp phát hiện các lỗ hổng bảo mật hoặc cuộc tấn công đang diễn ra.
4. Chia sẻ quy tắc cộng đồng: Contribute và share các rule phát hiện giúp update và cải tiến cơ chế phát hiện
5. Tạo giải pháp bảo mật tùy chỉnh: Kết hợp YARA với các phương pháp phân tích tĩnh và động, giám sát hành vi và sandboxing giúp tạo ra các giải pháp bảo mật hiệu quả
6. Phản ứng với sự cố : YARA hỗ trợ bằng cách quết và phân tích các tệp hoặc hình ảnh bộ nhớ để tìm các mẫu đặc trưng liên quan đến sự cố bảo mật

Cách Yara hoạt động:
Yara quét một tập hợp các tệp bằng cách so sánh nội dung của chúng với các mẫu đã được định nghĩa trong quy tắc YARA. Khi một tệp khớp với các mẫu trong điều kiện trong YAra, nó sẽ được xem là một tệp bị phát hiệ

Quá trình hoạt động gồm các bước sau:
1. Tập hợp quy tắc(Chứa các mẫu đáng ngờ): Quy tắc YARA được tạo bởi các nhà phân tích bảo mật. Các quy tắc này định nghĩa các mẫu, đặc điểm hoặc chỉ số cần phải khớp trong các tệp. Quy tắc thường đường lưu trong tệp quy tắc YARA (ví dụ .yara hoặc .yar)
2. Tập hợp các tệp (Để quét): Một tập hợp các tệp, chẳng hạn như tệp thưucj thi, tài liệu hoặc các tệp nhị phân sẽ cung cấp cho YARA để quét. Các tệp này có thể được lưu trữ trên đĩa cứng, trogn thư mục hoặc thậm chí trong các hình ảnh bộ nhớ hoặc bản sao lưu mạng
3.Công cụ quét YARA: sử dụng module YARA, một bộ thuật toán và kỹ thuật so sánh nội dung của tệp với các mẫu trong quy tắc
4. Quá trình quét và so khớp: Công cụ quét YARA sẽ lần lượt quét từng tệp trong tập hợp và phân tích nội dung từng tệp, tìm kiếm các mẫu khớp với quy tắc đã định nghĩa. Công cụ sử dụng nhiều kĩ thuật so khớp, bao gồm so khớp chuỗi, biểu thức chính quy và so khớp nhị phân.
5. Phát hiện tệp: Khi một tệp khớp với các mẫu và điều kiện trong quy tắc YARA, tệp đó được coi là đã bị phát hiện. Công cụ quét YARA sẽ ghi lại thông tin về các quy tắc đã khớp, đường dẫn tệp và vị trí tệp trong tệp nơi khớp đã xảy ra

Cấu trúc của một quy tắc YARA
1. Phần header: cung cấp metadata và xác định tên quy tắc
2. Phần meta: Định nghĩa các thông tin bổ sung như tác giả, mô tả,phiên bản và các thông tin khác.
3. Phần strings: Định nghĩa các chuỗi hoặc mẫu cần tìm trong tệp
4. Phần condition: Xác định điều kiện khi nào quy tắc sẽ kích hoạt

Ví dụ:
```yara
rule my_rule{
  meta:
    author = "Author Name"
    description = "Example rule"
    hash = ""

  strings:
    $string1 = "test"
    $string2 = "rule"
    $string3 = "htb"

  condition:
    all of them
}
```
Ví dụ về quy tắc phát hiện Wanacry:
```yara
rule Ransomware_WannaCry {
    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from WannaCry ransomware"
        reference = "https://www.virustotal.com/gui/file/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/behavior"
    
    strings:
        $wannacry_payload_str1 = "tasksche.exe" fullword ascii
        $wannacry_payload_str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $wannacry_payload_str3 = "mssecsvc.exe" fullword ascii
    
    condition:
        all of them
}

```